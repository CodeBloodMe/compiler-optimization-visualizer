use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use anyhow::{Context, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisPolicy {
    #[serde(default)]
    pub capabilities: CapabilityPolicy,
    #[serde(default)]
    pub resources: ResourcePolicy,
    #[serde(default)]
    pub security: SecurityPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CapabilityPolicy {
    #[serde(default = "default_false")]
    pub console_write: bool,
    #[serde(default = "default_false")]
    pub host_read: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourcePolicy {
    #[serde(default = "default_initial_fuel")]
    pub initial_fuel: u64,
    #[serde(default = "default_max_memory_pages")]
    pub max_memory_pages: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityPolicy {
    #[serde(default = "default_true")]
    pub strict_imports: bool,
    #[serde(default = "default_true")]
    pub deny_unknown_imports: bool,
}

fn default_false() -> bool {
    false
}

fn default_true() -> bool {
    true
}

fn default_initial_fuel() -> u64 {
    1_000_000
}

fn default_max_memory_pages() -> u32 {
    16
}

impl Default for AegisPolicy {
    fn default() -> Self {
        Self {
            capabilities: CapabilityPolicy {
                console_write: true,
                host_read: true,
            },
            resources: ResourcePolicy {
                initial_fuel: 1_000_000,
                max_memory_pages: 16,
            },
            security: SecurityPolicy {
                strict_imports: true,
                deny_unknown_imports: true,
            },
        }
    }
}

impl AegisPolicy {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read policy file at {:?}", path.as_ref()))?;
        let policy: AegisPolicy = toml::from_str(&content)
            .with_context(|| format!("Failed to parse TOML policy at {:?}", path.as_ref()))?;
        Ok(policy)
    }

    pub fn is_capability_granted(&self, cap: &str) -> bool {
        match cap {
            "console.write" => self.capabilities.console_write,
            "host.read" => self.capabilities.host_read,
            _ => false,
        }
    }
}
