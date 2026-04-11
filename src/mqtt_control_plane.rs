//! Minimal MQTT control-plane responder (policy + revocation sync).
//!
//! This module is a practical building block for fleet operations:
//! - clients publish sync requests to `pqc/policy/sync/v1` and `pqc/revocations/sync/v1`
//! - a gateway/CA service responds by re-publishing the latest signed updates as retained messages
//!   on `pqc/policy/v1` and `pqc/revocations/v1`
//!
//! Security model:
//! - the broker/network is untrusted; updates must be signed by the CA and verified by clients
//! - sync requests are unauthenticated hints; treat them as best-effort, rate-limited triggers

use crate::security::policy::FleetPolicyUpdate;
use crate::security::revocation::RevocationUpdate;
use crate::{Error, Result};
use log::{debug, info, warn};
use rumqttc::{Client, Event, MqttOptions, Packet, Publish, QoS};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_POLICY_TOPIC: &str = "pqc/policy/v1";
const DEFAULT_POLICY_SYNC_TOPIC: &str = "pqc/policy/sync/v1";
const DEFAULT_REVOCATION_TOPIC: &str = "pqc/revocations/v1";
const DEFAULT_REVOCATION_SYNC_TOPIC: &str = "pqc/revocations/sync/v1";

/// Hard DoS containment limit for sync request payloads.
const MAX_SYNC_REQUEST_BYTES: usize = 8 * 1024; // 8 KiB

#[derive(Debug, Serialize, Deserialize)]
struct FleetPolicySyncRequest {
    version: u8,
    client_id: String,
    current_seq: u64,
}

impl FleetPolicySyncRequest {
    const VERSION_V1: u8 = 1;
}

#[derive(Debug, Serialize, Deserialize)]
struct RevocationSyncRequest {
    version: u8,
    client_id: String,
    current_seq: u64,
}

impl RevocationSyncRequest {
    const VERSION_V1: u8 = 1;
}

/// Minimal control-plane service responding to sync requests.
///
/// This is not a full CA implementation; it only re-publishes signed policy/revocation updates
/// that are already produced by your operational tooling.
pub struct MqttControlPlane {
    options: MqttOptions,
    policy_topic: String,
    policy_sync_topic: String,
    revocation_topic: String,
    revocation_sync_topic: String,
    policy: Option<FleetPolicyUpdate>,
    revocation: Option<RevocationUpdate>,
}

impl MqttControlPlane {
    /// Create a new control-plane responder for a given MQTT broker endpoint.
    pub fn new(broker: &str, port: u16, client_id: &str) -> Self {
        let mut options = MqttOptions::new(client_id, broker, port);
        options.set_clean_session(true);
        options.set_keep_alive(Duration::from_secs(15));

        Self {
            options,
            policy_topic: DEFAULT_POLICY_TOPIC.to_string(),
            policy_sync_topic: DEFAULT_POLICY_SYNC_TOPIC.to_string(),
            revocation_topic: DEFAULT_REVOCATION_TOPIC.to_string(),
            revocation_sync_topic: DEFAULT_REVOCATION_SYNC_TOPIC.to_string(),
            policy: None,
            revocation: None,
        }
    }

    /// Override the fleet policy update topic.
    pub fn with_policy_topic(mut self, topic: &str) -> Self {
        self.policy_topic = topic.to_string();
        self
    }

    /// Override the fleet policy sync request topic.
    pub fn with_policy_sync_topic(mut self, topic: &str) -> Self {
        self.policy_sync_topic = topic.to_string();
        self
    }

    /// Override the revocation update topic.
    pub fn with_revocation_topic(mut self, topic: &str) -> Self {
        self.revocation_topic = topic.to_string();
        self
    }

    /// Override the revocation sync request topic.
    pub fn with_revocation_sync_topic(mut self, topic: &str) -> Self {
        self.revocation_sync_topic = topic.to_string();
        self
    }

    /// Install the latest signed fleet policy update to be served.
    pub fn set_policy_update(&mut self, update: FleetPolicyUpdate) {
        self.policy = Some(update);
    }

    /// Install the latest signed revocation update to be served.
    pub fn set_revocation_update(&mut self, update: RevocationUpdate) {
        self.revocation = Some(update);
    }

    /// Publish the currently configured updates as retained messages (best-effort).
    pub fn publish_retained(&self) -> Result<()> {
        let (mut client, mut conn) = Client::new(self.options.clone(), 20);

        // Drain connection progress in a background thread.
        let handle = std::thread::spawn(move || {
            for notification in conn.iter() {
                if notification.is_err() {
                    break;
                }
            }
        });

        if let Some(policy) = &self.policy {
            let payload = serde_json::to_vec(policy)
                .map_err(|e| Error::ClientError(format!("FleetPolicyUpdate JSON error: {}", e)))?;
            client
                .publish(&self.policy_topic, QoS::AtLeastOnce, true, payload)
                .map_err(|e| Error::MqttError(e.to_string()))?;
        }
        if let Some(rev) = &self.revocation {
            let payload = serde_json::to_vec(rev)
                .map_err(|e| Error::ClientError(format!("RevocationUpdate JSON error: {}", e)))?;
            client
                .publish(&self.revocation_topic, QoS::AtLeastOnce, true, payload)
                .map_err(|e| Error::MqttError(e.to_string()))?;
        }

        let _ = client.disconnect();
        let _ = handle.join();
        Ok(())
    }

    /// Run the sync responder loop (blocking).
    ///
    /// Intended usage: run this in a dedicated gateway/CA process/thread.
    pub fn run(mut self) -> Result<()> {
        let (mut client, mut conn) = Client::new(self.options.clone(), 50);
        client
            .subscribe(self.policy_sync_topic.as_str(), QoS::AtLeastOnce)
            .map_err(|e| Error::MqttError(e.to_string()))?;
        client
            .subscribe(self.revocation_sync_topic.as_str(), QoS::AtLeastOnce)
            .map_err(|e| Error::MqttError(e.to_string()))?;

        info!(
            "control-plane responder online: policy_topic={} revocation_topic={} policy_sync_topic={} revocation_sync_topic={}",
            self.policy_topic, self.revocation_topic, self.policy_sync_topic, self.revocation_sync_topic
        );

        for notification in conn.iter() {
            let event = match notification {
                Ok(e) => e,
                Err(e) => {
                    warn!("control-plane mqtt connection error: {}", e);
                    continue;
                }
            };
            if let Event::Incoming(Packet::Publish(publish)) = event {
                let _ = self.handle_publish(&mut client, publish);
            }
        }

        Ok(())
    }

    fn handle_publish(&mut self, client: &mut Client, publish: Publish) -> Result<()> {
        let topic = publish.topic.as_str();
        if publish.payload.len() > MAX_SYNC_REQUEST_BYTES {
            warn!(
                "dropping sync request: payload too large ({} bytes > {}) topic={}",
                publish.payload.len(),
                MAX_SYNC_REQUEST_BYTES,
                topic
            );
            return Ok(());
        }

        if topic == self.policy_sync_topic {
            let req: FleetPolicySyncRequest = match serde_json::from_slice(&publish.payload) {
                Ok(v) => v,
                Err(e) => {
                    warn!("invalid FleetPolicySyncRequest JSON: {}", e);
                    return Ok(());
                }
            };
            if req.version != FleetPolicySyncRequest::VERSION_V1 {
                warn!(
                    "ignoring FleetPolicySyncRequest: unsupported version={} client_id={}",
                    req.version, req.client_id
                );
                return Ok(());
            }
            let latest = match &self.policy {
                Some(p) => p,
                None => return Ok(()),
            };
            if req.current_seq < latest.seq {
                debug!(
                    "serving fleet policy to client_id={} current_seq={} latest_seq={}",
                    req.client_id, req.current_seq, latest.seq
                );
                let payload = serde_json::to_vec(latest).map_err(|e| {
                    Error::ClientError(format!("FleetPolicyUpdate JSON error: {}", e))
                })?;
                client
                    .publish(&self.policy_topic, QoS::AtLeastOnce, true, payload)
                    .map_err(|e| Error::MqttError(e.to_string()))?;
            }
            return Ok(());
        }

        if topic == self.revocation_sync_topic {
            let req: RevocationSyncRequest = match serde_json::from_slice(&publish.payload) {
                Ok(v) => v,
                Err(e) => {
                    warn!("invalid RevocationSyncRequest JSON: {}", e);
                    return Ok(());
                }
            };
            if req.version != RevocationSyncRequest::VERSION_V1 {
                warn!(
                    "ignoring RevocationSyncRequest: unsupported version={} client_id={}",
                    req.version, req.client_id
                );
                return Ok(());
            }
            let latest = match &self.revocation {
                Some(r) => r,
                None => return Ok(()),
            };
            if req.current_seq < latest.seq {
                debug!(
                    "serving revocation update to client_id={} current_seq={} latest_seq={}",
                    req.client_id, req.current_seq, latest.seq
                );
                let payload = serde_json::to_vec(latest).map_err(|e| {
                    Error::ClientError(format!("RevocationUpdate JSON error: {}", e))
                })?;
                client
                    .publish(&self.revocation_topic, QoS::AtLeastOnce, true, payload)
                    .map_err(|e| Error::MqttError(e.to_string()))?;
            }
            return Ok(());
        }

        Ok(())
    }
}
