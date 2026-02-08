use serde::Deserialize;
use std::path::PathBuf;

/// Server configuration loaded from TOML file.
/// See config.toml.example for format.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// TCP port to listen on (default 445, use 4450 for non-root)
    pub port: u16,
    /// Server name advertised in NEGOTIATE response
    pub server_name: String,
    /// List of shared directories
    pub shares: Vec<ShareConfig>,
    /// Configured user accounts (empty = guest-only)
    #[serde(default)]
    pub users: Vec<UserConfig>,
}

/// A single shared directory configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct ShareConfig {
    /// Share name as seen by clients (e.g. "Public")
    pub name: String,
    /// Local filesystem path to share
    pub path: PathBuf,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub guest_ok: bool,
}

/// A configured user account.
#[derive(Debug, Deserialize, Clone)]
pub struct UserConfig {
    pub username: String,
    pub password: String,
}

/// Load and parse the TOML configuration file.
pub fn load_config(path: &str) -> anyhow::Result<Config> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read config file '{}': {}", path, e))?;
    let config: Config = toml::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse config file '{}': {}", path, e))?;
    if config.shares.is_empty() {
        anyhow::bail!("No shares configured");
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let toml_str = r#"
            port = 4450
            server_name = "test"
            [[shares]]
            name = "Public"
            path = "/tmp"
            guest_ok = true
            [[users]]
            username = "alice"
            password = "pass"
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.port, 4450);
        assert_eq!(config.shares.len(), 1);
        assert!(config.shares[0].guest_ok);
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.users[0].username, "alice");
    }
}
