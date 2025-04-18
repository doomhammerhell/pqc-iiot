//! Configuration management for cryptographic profiles.
//!
//! This module provides functionality to load and manage configuration settings
//! for cryptographic profiles from various sources (TOML files, environment variables).

use core::fmt;
use serde::{Deserialize, Serialize};

/// Error type for configuration operations
#[derive(Debug)]
pub enum ConfigError {
    /// Failed to load configuration file
    LoadError(String),
    /// Invalid configuration value
    InvalidValue(String),
    /// Missing required configuration
    MissingConfig(String),
    /// Configuration parsing error
    ParseError(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::LoadError(e) => write!(f, "Failed to load configuration: {}", e),
            ConfigError::InvalidValue(e) => write!(f, "Invalid configuration value: {}", e),
            ConfigError::MissingConfig(e) => write!(f, "Missing required configuration: {}", e),
            ConfigError::ParseError(e) => write!(f, "Configuration parsing error: {}", e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ConfigError {}

/// Configuration settings for cryptographic profiles
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// Default profile settings
    pub profiles: ProfileConfig,
    /// Hardware acceleration settings
    pub hardware: HardwareConfig,
    /// Memory management settings
    pub memory: MemoryConfig,
    /// Logging settings
    pub logging: LoggingConfig,
}

/// Profile configuration settings
#[derive(Debug, Serialize, Deserialize)]
pub struct ProfileConfig {
    /// Default profile to use
    pub default: DefaultProfileConfig,
    /// Security level settings
    pub security: SecurityConfig,
    /// Key rotation settings
    pub rotation: RotationConfig,
    /// Performance monitoring settings
    pub metrics: MetricsConfig,
    /// Profile-specific settings
    pub kyber_falcon: KyberFalconConfig,
    pub saber_dilithium: SaberDilithiumConfig,
    pub kyber_dilithium: KyberDilithiumConfig,
}

/// Default profile configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct DefaultProfileConfig {
    /// Default profile name
    pub profile: String,
}

/// Security level configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Default security level
    pub level: u32,
}

/// Key rotation configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct RotationConfig {
    /// Key rotation interval in seconds
    pub interval: u64,
}

/// Performance metrics configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable performance metrics
    pub enabled: bool,
    /// Metrics collection interval in seconds
    pub interval: u64,
}

/// Kyber + Falcon profile configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct KyberFalconConfig {
    /// Kyber security level
    pub kyber_level: u32,
    /// Falcon security level
    pub falcon_level: u32,
}

/// SABER + Dilithium profile configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct SaberDilithiumConfig {
    /// SABER security level
    pub saber_level: String,
    /// Dilithium security level
    pub dilithium_level: u32,
}

/// Kyber + Dilithium profile configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct KyberDilithiumConfig {
    /// Kyber security level
    pub kyber_level: u32,
    /// Dilithium security level
    pub dilithium_level: u32,
}

/// Hardware acceleration configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct HardwareConfig {
    /// Enable hardware acceleration
    pub enabled: bool,
    /// Preferred acceleration method
    pub preferred: String,
}

/// Memory management configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct MemoryConfig {
    /// Maximum static memory allocation
    pub max_static: usize,
    /// Maximum dynamic memory allocation
    pub max_dynamic: usize,
    /// Enable memory zeroization
    pub zeroize: bool,
}

/// Logging configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,
    /// Enable performance logging
    pub performance: bool,
    /// Enable security event logging
    pub security: bool,
}

impl Config {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        Self {
            profiles: ProfileConfig {
                default: DefaultProfileConfig {
                    profile: "ProfileKyberDilithium".to_string(),
                },
                security: SecurityConfig {
                    level: 3,
                },
                rotation: RotationConfig {
                    interval: 3600,
                },
                metrics: MetricsConfig {
                    enabled: true,
                    interval: 60,
                },
                kyber_falcon: KyberFalconConfig {
                    kyber_level: 768,
                    falcon_level: 512,
                },
                saber_dilithium: SaberDilithiumConfig {
                    saber_level: "L3".to_string(),
                    dilithium_level: 3,
                },
                kyber_dilithium: KyberDilithiumConfig {
                    kyber_level: 768,
                    dilithium_level: 3,
                },
            },
            hardware: HardwareConfig {
                enabled: true,
                preferred: "aesni".to_string(),
            },
            memory: MemoryConfig {
                max_static: 16384,
                max_dynamic: 65536,
                zeroize: true,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                performance: true,
                security: true,
            },
        }
    }

    #[cfg(feature = "std")]
    /// Load configuration from a TOML file
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        use std::fs;

        let contents = fs::read_to_string(path)
            .map_err(|e| ConfigError::LoadError(e.to_string()))?;

        toml::from_str(&contents)
            .map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    #[cfg(feature = "std")]
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, ConfigError> {
        use std::env;

        let mut config = Self::new();

        if let Ok(profile) = env::var("PQC_IIOT_PROFILE") {
            config.profiles.default.profile = profile;
        }

        if let Ok(level) = env::var("PQC_IIOT_SECURITY_LEVEL") {
            config.profiles.security.level = level.parse()
                .map_err(|_| ConfigError::InvalidValue("security level".to_string()))?;
        }

        if let Ok(interval) = env::var("PQC_IIOT_ROTATION_INTERVAL") {
            config.profiles.rotation.interval = interval.parse()
                .map_err(|_| ConfigError::InvalidValue("rotation interval".to_string()))?;
        }

        Ok(config)
    }

    /// Get the default profile name
    pub fn default_profile(&self) -> &str {
        &self.profiles.default.profile
    }

    /// Get the security level
    pub fn security_level(&self) -> u32 {
        self.profiles.security.level
    }

    /// Get the key rotation interval
    pub fn rotation_interval(&self) -> u64 {
        self.profiles.rotation.interval
    }

    /// Check if performance metrics are enabled
    pub fn metrics_enabled(&self) -> bool {
        self.profiles.metrics.enabled
    }

    /// Get the metrics collection interval
    pub fn metrics_interval(&self) -> u64 {
        self.profiles.metrics.interval
    }
} 