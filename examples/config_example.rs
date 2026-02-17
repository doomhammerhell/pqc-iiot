//! Example demonstrating the use of cryptographic profiles with external configuration.
//!
//! This example shows how to:
//! 1. Load configuration from a TOML file
//! 2. Load configuration from environment variables
//! 3. Create profiles based on configuration
//! 4. Use the configured profiles for cryptographic operations

use pqc_iiot::{
    config::Config,
    crypto::profile::ProfileKyberFalcon,
};
#[cfg(feature = "dilithium")]
use pqc_iiot::crypto::profile::{ProfileKyberDilithium, ProfileSaberDilithium};
// use pqc_iiot::crypto::traits::*;
use pqc_iiot::crypto::profile::CryptoProfileTrait;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example 1: Load configuration from TOML file
    println!("Example 1: Loading configuration from TOML file");
    toml_config_example()?;

    // Example 2: Load configuration from environment variables
    println!("\nExample 2: Loading configuration from environment variables");
    env_config_example()?;

    // Example 3: Use default configuration
    println!("\nExample 3: Using default configuration");
    default_config_example()?;

    Ok(())
}

fn toml_config_example() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from TOML file
    let config = Config::from_file("config/default.toml")?;
    println!("Loaded configuration:");
    println!("- Default profile: {}", config.default_profile());
    println!("- Security level: {}", config.security_level());
    println!(
        "- Rotation interval: {} seconds",
        config.rotation_interval()
    );
    println!("- Metrics enabled: {}", config.metrics_enabled());
    println!("- Metrics interval: {} seconds", config.metrics_interval());

    // Create profile based on configuration
    let profile = match config.default_profile() {
        "ProfileKyberFalcon" => Box::new(ProfileKyberFalcon::new()) as Box<dyn CryptoProfileTrait>,
        #[cfg(all(feature = "saber", feature = "dilithium"))]
        "ProfileSaberDilithium" => {
            Box::new(ProfileSaberDilithium::new()) as Box<dyn CryptoProfileTrait>
        }
        #[cfg(feature = "dilithium")]
        "ProfileKyberDilithium" => {
            Box::new(ProfileKyberDilithium::new()) as Box<dyn CryptoProfileTrait>
        }
        _ => return Err("Invalid profile name".into()),
    };

    // Use the profile
    let (pk, sk) = profile.generate_keypair()?;
    println!(
        "Generated key pair (public key: {} bytes, secret key: {} bytes)",
        pk.len(),
        sk.len()
    );

    Ok(())
}

fn env_config_example() -> Result<(), Box<dyn std::error::Error>> {
    // Set environment variables
    std::env::set_var("PQC_IIOT_PROFILE", "ProfileKyberFalcon");
    std::env::set_var("PQC_IIOT_SECURITY_LEVEL", "3");
    std::env::set_var("PQC_IIOT_ROTATION_INTERVAL", "3600");

    // Load configuration from environment variables
    let config = Config::from_env()?;
    println!("Loaded configuration from environment:");
    println!("- Default profile: {}", config.default_profile());
    println!("- Security level: {}", config.security_level());
    println!(
        "- Rotation interval: {} seconds",
        config.rotation_interval()
    );

    // Create profile based on configuration
    let profile = match config.default_profile() {
        "ProfileKyberFalcon" => Box::new(ProfileKyberFalcon::new()) as Box<dyn CryptoProfileTrait>,
        #[cfg(all(feature = "saber", feature = "dilithium"))]
        "ProfileSaberDilithium" => {
            Box::new(ProfileSaberDilithium::new()) as Box<dyn CryptoProfileTrait>
        }
        #[cfg(feature = "dilithium")]
        "ProfileKyberDilithium" => {
            Box::new(ProfileKyberDilithium::new()) as Box<dyn CryptoProfileTrait>
        }
        _ => return Err("Invalid profile name".into()),
    };

    // Use the profile
    let (pk, sk) = profile.generate_keypair()?;
    println!(
        "Generated key pair (public key: {} bytes, secret key: {} bytes)",
        pk.len(),
        sk.len()
    );

    Ok(())
}

fn default_config_example() -> Result<(), Box<dyn std::error::Error>> {
    // Use default configuration
    let config = Config::new();
    println!("Using default configuration:");
    println!("- Default profile: {}", config.default_profile());
    println!("- Security level: {}", config.security_level());
    println!(
        "- Rotation interval: {} seconds",
        config.rotation_interval()
    );
    println!("- Metrics enabled: {}", config.metrics_enabled());
    println!("- Metrics interval: {} seconds", config.metrics_interval());

    // Create profile based on default configuration
    let profile = match config.default_profile() {
        "ProfileKyberFalcon" => Box::new(ProfileKyberFalcon::new()) as Box<dyn CryptoProfileTrait>,
        #[cfg(all(feature = "saber", feature = "dilithium"))]
        "ProfileSaberDilithium" => {
            Box::new(ProfileSaberDilithium::new()) as Box<dyn CryptoProfileTrait>
        }
        #[cfg(feature = "dilithium")]
        "ProfileKyberDilithium" => {
            Box::new(ProfileKyberDilithium::new()) as Box<dyn CryptoProfileTrait>
        }
        _ => return Err("Invalid profile name".into()),
    };

    // Use the profile
    let (pk, sk) = profile.generate_keypair()?;
    println!(
        "Generated key pair (public key: {} bytes, secret key: {} bytes)",
        pk.len(),
        sk.len()
    );

    Ok(())
}
