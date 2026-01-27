use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};

// Re-export types from acl-engine-r
pub use acl_engine_r::{AutoGeoLoader, GeoIpFormat, GeoSiteFormat, HostInfo, NilGeoLoader, Protocol};
use eyre::{Context, Result};
use serde::{Deserialize, Serialize};

/// ACL configuration loaded from YAML file
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct AclConfig {
	/// List of outbound configurations
	#[serde(default)]
	pub outbounds: Vec<OutboundEntry>,

	/// ACL rules configuration
	#[serde(default)]
	pub acl: AclRules,
}

/// Single outbound entry
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct OutboundEntry {
	/// Outbound name (used in rules)
	pub name: String,

	/// Outbound type
	#[serde(rename = "type")]
	pub outbound_type: String,

	/// Type-specific configuration (flattened)
	#[serde(flatten)]
	pub config: OutboundEntryConfig,
}

/// Outbound configuration variants
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum OutboundEntryConfig {
	/// SOCKS5 proxy configuration
	Socks5 { socks5: Socks5Config },
	/// Direct connection configuration
	Direct {
		#[serde(skip_serializing_if = "Option::is_none")]
		direct: Option<DirectConfig>,
	},
}

/// Direct connection configuration
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct DirectConfig {
	/// IP mode: auto, 4 (v4only), 6 (v6only)
	#[serde(default = "default_mode")]
	pub mode: IpMode,
}

fn default_mode() -> IpMode {
	IpMode::Auto
}

/// IP mode for direct connections
#[derive(Deserialize, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IpMode {
	#[serde(rename = "auto")]
	Auto,
	#[serde(rename = "4")]
	V4Only,
	#[serde(rename = "6")]
	V6Only,
}

/// SOCKS5 proxy configuration
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Socks5Config {
	/// SOCKS5 server address (e.g., "127.0.0.1:1080")
	pub addr: String,

	/// Optional username for authentication
	#[serde(skip_serializing_if = "Option::is_none")]
	pub username: Option<String>,

	/// Optional password for authentication
	#[serde(skip_serializing_if = "Option::is_none")]
	pub password: Option<String>,

	/// Whether to allow UDP relay
	#[serde(default)]
	pub allow_udp: bool,
}

/// ACL rules configuration
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct AclRules {
	/// Inline rules as strings (e.g., "direct(all)")
	#[serde(default)]
	pub inline: Vec<String>,
}

/// Outbound handler type
#[derive(Clone, Debug)]
pub enum OutboundHandler {
	/// Direct connection
	Direct { mode: IpMode },
	/// SOCKS5 proxy
	Socks5 { config: Socks5Config },
	/// Reject connection
	Reject,
}

impl OutboundHandler {
	/// Create OutboundHandler from OutboundEntry
	pub fn from_entry(entry: &OutboundEntry) -> Result<Self> {
		match entry.outbound_type.as_str() {
			"direct" => match &entry.config {
				OutboundEntryConfig::Direct { direct } => {
					let mode = direct.as_ref().map(|d| d.mode).unwrap_or(IpMode::Auto);
					Ok(OutboundHandler::Direct { mode })
				}
				_ => eyre::bail!("Invalid config for direct outbound '{}'", entry.name),
			},
			"socks5" => match &entry.config {
				OutboundEntryConfig::Socks5 { socks5 } => Ok(OutboundHandler::Socks5 { config: socks5.clone() }),
				_ => eyre::bail!("Invalid config for socks5 outbound '{}'", entry.name),
			},
			"reject" => Ok(OutboundHandler::Reject),
			unknown => eyre::bail!("Unknown outbound type '{}' for outbound '{}'", unknown, entry.name),
		}
	}
}

/// ACL Engine wrapper
pub struct AclEngine {
	// Compiled rule set from acl-engine-r
	compiled:  acl_engine_r::CompiledRuleSet<Arc<OutboundHandler>>,
	// Keep outbounds map for reference
	outbounds: HashMap<String, Arc<OutboundHandler>>,
}

impl AclEngine {
	/// Create new ACL engine from configuration
	pub async fn new(acl_config: AclConfig, data_dir: impl AsRef<Path>, refresh_geodata: bool) -> Result<Self> {
		// Parse outbounds into handler map
		let mut outbounds: HashMap<String, Arc<OutboundHandler>> = HashMap::new();

		for entry in &acl_config.outbounds {
			let handler =
				OutboundHandler::from_entry(entry).with_context(|| format!("Failed to parse outbound '{}'", entry.name))?;
			outbounds.insert(entry.name.clone(), Arc::new(handler));
		}

		// If no outbounds defined, create default direct outbound
		if outbounds.is_empty() {
			tracing::debug!("No outbounds defined, creating default direct outbound");
			outbounds.insert(
				"default".to_string(),
				Arc::new(OutboundHandler::Direct { mode: IpMode::Auto }),
			);
		}

		// Get rules or use default
		let rules = if acl_config.acl.inline.is_empty() {
			tracing::debug!("No ACL rules defined, using default 'default(all)' rule");
			vec!["default(all)".to_string()]
		} else {
			acl_config.acl.inline.clone()
		};

		// Parse rules text
		let rules_text = rules.join("\n");
		let text_rules = acl_engine_r::parse_rules(&rules_text).with_context(|| "Failed to parse ACL rules")?;

		// Create AutoGeoLoader with MMDB for GeoIP and Sing (DB) for GeoSite
		let mut geo_loader = AutoGeoLoader::new()
			.with_data_dir(data_dir)
			.with_geoip(GeoIpFormat::Mmdb)
			.with_geosite(GeoSiteFormat::Sing);

		// Force refresh geodata if requested
		if refresh_geodata {
			tracing::info!("Force refreshing geoip and geosite databases");
			geo_loader = geo_loader.with_update_interval(Duration::ZERO);
		}

		// Compile rules with outbound map and AutoGeoLoader
		let compiled =
			acl_engine_r::compile(&text_rules, &outbounds, 1024, &geo_loader).with_context(|| "Failed to compile ACL rules")?;

		tracing::info!(
			"ACL engine initialized with {} outbounds and {} rules",
			outbounds.len(),
			compiled.rule_count()
		);

		Ok(Self { compiled, outbounds })
	}

	/// Match a host against ACL rules
	pub fn match_host(&self, host: &str, port: u16, protocol: Protocol) -> Option<Arc<OutboundHandler>> {
		// Create HostInfo from domain or IP
		let host_info = if host.parse::<std::net::IpAddr>().is_ok() {
			acl_engine_r::HostInfo::new("", Some(host.parse().unwrap()), None)
		} else {
			acl_engine_r::HostInfo::from_name(host)
		};

		// Match against compiled rules
		match self.compiled.match_host(&host_info, protocol, port) {
			Some(result) => Some(result.outbound.clone()),
			None => {
				// No match, try to return default outbound
				self.outbounds
					.get("default")
					.or_else(|| self.outbounds.get("direct"))
					.or_else(|| self.outbounds.values().next())
					.cloned()
			}
		}
	}
}

/// Create a default ACL engine with direct routing for all traffic
pub async fn create_default_engine(data_dir: impl AsRef<Path>, refresh_geodata: bool) -> Result<AclEngine> {
	let default_config = AclConfig {
		outbounds: vec![OutboundEntry {
			name:          "default".to_string(),
			outbound_type: "direct".to_string(),
			config:        OutboundEntryConfig::Direct {
				direct: Some(DirectConfig { mode: IpMode::Auto }),
			},
		}],
		acl:       AclRules {
			inline: vec!["default(all)".to_string()],
		},
	};

	AclEngine::new(default_config, data_dir, refresh_geodata).await
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn test_parse_basic_acl_config() {
		let yaml = r#"
outbounds:
  - name: direct
    type: direct
    direct:
      mode: auto

acl:
  inline:
    - direct(all)
"#;
		let config: AclConfig = serde_yaml::from_str(yaml).expect("Failed to parse YAML");
		assert_eq!(config.outbounds.len(), 1);
		assert_eq!(config.outbounds[0].name, "direct");
		assert_eq!(config.acl.inline.len(), 1);
		assert_eq!(config.acl.inline[0], "direct(all)");
	}

	#[tokio::test]
	async fn test_parse_socks5_config() {
		let yaml = r#"
outbounds:
  - name: proxy
    type: socks5
    socks5:
      addr: 127.0.0.1:1080
      username: user
      password: pass
      allow_udp: true

acl:
  inline:
    - proxy(all)
"#;
		let config: AclConfig = serde_yaml::from_str(yaml).expect("Failed to parse YAML");
		assert_eq!(config.outbounds.len(), 1);
		assert_eq!(config.outbounds[0].name, "proxy");
		assert_eq!(config.outbounds[0].outbound_type, "socks5");

		match &config.outbounds[0].config {
			OutboundEntryConfig::Socks5 { socks5 } => {
				assert_eq!(socks5.addr, "127.0.0.1:1080");
				assert_eq!(socks5.username, Some("user".to_string()));
				assert_eq!(socks5.password, Some("pass".to_string()));
				assert!(socks5.allow_udp);
			}
			_ => panic!("Expected Socks5 config"),
		}
	}

	#[tokio::test]
	async fn test_acl_engine_creation() {
		let temp_dir = tempfile::tempdir().unwrap();
		let config = AclConfig {
			outbounds: vec![OutboundEntry {
				name:          "direct".to_string(),
				outbound_type: "direct".to_string(),
				config:        OutboundEntryConfig::Direct {
					direct: Some(DirectConfig { mode: IpMode::Auto }),
				},
			}],
			acl:       AclRules {
				inline: vec!["direct(all)".to_string()],
			},
		};

		let engine = AclEngine::new(config, temp_dir.path(), false)
			.await
			.expect("Failed to create ACL engine");

		// Test matching a domain
		let result = engine.match_host("example.com", 80, Protocol::TCP);
		assert!(result.is_some());

		match result.unwrap().as_ref() {
			OutboundHandler::Direct { mode } => {
				assert_eq!(*mode, IpMode::Auto);
			}
			_ => panic!("Expected Direct handler"),
		}
	}

	#[tokio::test]
	async fn test_acl_reject_handler() {
		let temp_dir = tempfile::tempdir().unwrap();
		let config = AclConfig {
			outbounds: vec![
				OutboundEntry {
					name:          "reject".to_string(),
					outbound_type: "reject".to_string(),
					config:        OutboundEntryConfig::Direct { direct: None },
				},
				OutboundEntry {
					name:          "direct".to_string(),
					outbound_type: "direct".to_string(),
					config:        OutboundEntryConfig::Direct {
						direct: Some(DirectConfig { mode: IpMode::Auto }),
					},
				},
			],
			acl:       AclRules {
				inline: vec!["reject(all, udp/443)".to_string(), "direct(all)".to_string()],
			},
		};

		let engine = AclEngine::new(config, temp_dir.path(), false)
			.await
			.expect("Failed to create ACL engine");

		// Test UDP/443 is rejected
		let result = engine.match_host("example.com", 443, Protocol::UDP);
		assert!(result.is_some());
		assert!(matches!(result.unwrap().as_ref(), OutboundHandler::Reject));

		// Test TCP/443 is not rejected
		let result = engine.match_host("example.com", 443, Protocol::TCP);
		assert!(result.is_some());
		assert!(matches!(result.unwrap().as_ref(), OutboundHandler::Direct { .. }));
	}

	#[tokio::test]
	async fn test_create_default_engine() {
		let temp_dir = tempfile::tempdir().unwrap();
		let engine = create_default_engine(temp_dir.path(), false)
			.await
			.expect("Failed to create default engine");

		// Test that default engine allows everything
		let result = engine.match_host("example.com", 80, Protocol::TCP);
		assert!(result.is_some());
		assert!(matches!(result.unwrap().as_ref(), OutboundHandler::Direct { .. }));
	}

	#[test]
	fn test_ip_mode_serialization() {
		assert_eq!(serde_yaml::to_string(&IpMode::Auto).unwrap().trim(), "auto");
		assert_eq!(serde_yaml::to_string(&IpMode::V4Only).unwrap().trim(), "'4'");
		assert_eq!(serde_yaml::to_string(&IpMode::V6Only).unwrap().trim(), "'6'");
	}

	#[test]
	fn test_ip_mode_deserialization() {
		let auto: IpMode = serde_yaml::from_str("auto").unwrap();
		assert_eq!(auto, IpMode::Auto);

		let v4: IpMode = serde_yaml::from_str("\"4\"").unwrap();
		assert_eq!(v4, IpMode::V4Only);

		let v6: IpMode = serde_yaml::from_str("\"6\"").unwrap();
		assert_eq!(v6, IpMode::V6Only);
	}
}
