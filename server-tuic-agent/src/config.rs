use std::{path::PathBuf, time::Duration};

use clap::{Parser, ValueEnum};
use educe::Educe;
use figment::{
	Figment,
	providers::{Format, Serialized, Toml},
};
use panel_connect_rpc::IpVersion;
use serde::{Deserialize, Serialize, de::IgnoredAny};
use tracing::{level_filters::LevelFilter, warn};

use crate::utils::CongestionController;

/// Parse IP version string (v4, v6, auto) into IpVersion enum
fn parse_ip_version(s: &str) -> Result<IpVersion, String> {
	match s.to_lowercase().as_str() {
		"v4" | "ipv4" | "4" => Ok(IpVersion::V4),
		"v6" | "ipv6" | "6" => Ok(IpVersion::V6),
		"auto" => Ok(IpVersion::Auto),
		_ => Err(format!("invalid ip version '{s}', expected v4, v6, or auto")),
	}
}


/// Control flow results for CLI parsing
#[derive(Debug)]
pub struct Control(&'static str);

impl std::fmt::Display for Control {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl std::error::Error for Control {}

/// TUIC Server - A minimalistic TUIC server implementation
#[derive(Parser, Debug)]
#[command(name = "server")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
	/// Path to the external config file (optional)
	#[arg(long = "ext_conf_file", value_name = "PATH")]
	pub ext_conf_file: Option<PathBuf>,

	/// Path to the ACL config file (optional, YAML format)
	#[arg(long = "acl_conf_file", value_name = "PATH")]
	pub acl_conf_file: Option<PathBuf>,

	/// Generate example configuration files (config.toml.example and
	/// acl.yaml.example)
	#[arg(short, long)]
	pub init: bool,

	/// Path to the certificate file
	#[arg(long = "cert_file", value_name = "PATH", default_value = "/root/.cert/server.crt")]
	pub cert_file: PathBuf,

	/// Path to the private key file
	#[arg(long = "key_file", value_name = "PATH", default_value = "/root/.cert/server.key")]
	pub key_file: PathBuf,

	/// Log mode
	#[arg(long = "log_mode", value_name = "MODE", default_value = "info")]
	pub log_mode: LogLevel,

	/// Panel server host (e.g., "127.0.0.1")
	#[arg(long = "server_host", value_name = "HOST", default_value = "127.0.0.1")]
	pub host: String,

	/// Panel server port (e.g., 8082)
	#[arg(long = "port", value_name = "PORT", default_value = "8082")]
	pub port: u16,

	/// Node ID (required for running server, not needed for --init)
	#[arg(long, value_name = "ID")]
	pub node: Option<u32>,

	/// API request cycle for fetching users (in seconds)
	#[arg(long = "fetch_users_interval", value_name = "SECONDS", default_value = "60")]
	pub fetch_users_interval: u64,

	/// API request cycle for reporting traffic stats (in seconds)
	#[arg(long = "report_traffics_interval", value_name = "SECONDS", default_value = "100")]
	pub report_traffics_interval: u64,

	/// API request cycle for heartbeat (in seconds)
	#[arg(long = "heartbeat_interval", value_name = "SECONDS", default_value = "180")]
	pub heartbeat_interval: u64,

	/// Data directory for persisting state and other data
	#[arg(long = "data_dir", value_name = "PATH", default_value = "/var/lib/tuic-agent-node")]
	pub data_dir: PathBuf,

	/// Panel request timeout (in seconds)
	#[arg(long = "timeout", value_name = "SECONDS", default_value = "15")]
	pub request_timeout: u64,

	/// TLS server name (SNI) for panel connection (defaults to --server_host)
	#[arg(long = "server_name", value_name = "NAME")]
	pub server_name: Option<String>,

	/// CA certificate path for panel TLS (omit for system trust store)
	#[arg(long = "ca_file", value_name = "PATH")]
	pub ca_cert: Option<String>,

	/// Force refresh geoip and geosite databases on startup
	#[arg(long = "refresh_geodata", default_value = "false")]
	pub refresh_geodata: bool,

	/// IP version for panel API connections: v4, v6, or auto (default: v4)
	#[arg(
		long = "panel_ip_version",
		value_name = "VERSION",
		default_value = "v4",
		value_parser = parse_ip_version,
	)]
	pub panel_ip_version: IpVersion,
}

#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
	/// Server port (set from panel API during init)
	#[serde(skip)]
	pub server_port: u16,

	/// Old server field (deprecated, port now fetched from panel API)
	#[serde(default, skip_serializing, rename = "server")]
	#[deprecated]
	pub __server: Option<serde::de::IgnoredAny>,

	/// Users config (deprecated, now fetched from panel API)
	#[serde(default, skip_serializing, rename = "users")]
	#[deprecated]
	pub __users: Option<serde::de::IgnoredAny>,

	/// Log mode (set from CLI, not config file)
	#[serde(skip)]
	pub log_mode:  LogLevel,
	/// Certificate file path (set from CLI, not config file)
	#[serde(skip)]
	pub cert_file: PathBuf,
	/// Private key file path (set from CLI, not config file)
	#[serde(skip)]
	pub key_file:  PathBuf,

	/// Panel configuration (set from CLI, not config file)
	#[serde(skip)]
	pub panel: Option<crate::panel::PanelConfig>,

	pub quic: QuicConfig,

	#[educe(Default = true)]
	pub udp_relay_ipv6: bool,

	/// Congestion control algorithm (set from panel API during init)
	#[serde(skip)]
	pub congestion_control: CongestionController,

	/// Zero RTT handshake (set from panel API during init)
	#[serde(skip)]
	pub zero_rtt_handshake: bool,

	/// Server name (set from panel API during init).
	#[serde(skip)]
	pub server_name: Option<String>,

	/// Old zero_rtt_handshake field (deprecated, now fetched from panel API)
	#[serde(default, skip_serializing, rename = "zero_rtt_handshake")]
	#[deprecated]
	pub __zero_rtt_handshake: Option<serde::de::IgnoredAny>,

	#[educe(Default = true)]
	pub dual_stack: bool,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(3)))]
	pub auth_timeout: Duration,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(3)))]
	pub task_negotiation_timeout: Duration,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(10)))]
	pub gc_interval: Duration,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(30)))]
	pub gc_lifetime: Duration,

	#[educe(Default = 1500)]
	pub max_external_packet_size: usize,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(60)))]
	pub stream_timeout: Duration,

	/// ACL engine for rule-based routing (loaded from --acl_conf_file)
	#[serde(skip)]
	pub acl_engine: Option<std::sync::Arc<crate::acl::AclEngine>>,

	pub experimental: ExperimentalConfig,

	/// Old configuration fields (deprecated, kept for migration)
	#[serde(default, skip_serializing, rename = "tls")]
	#[deprecated]
	pub __tls:                Option<serde::de::IgnoredAny>,
	#[serde(default, skip_serializing, rename = "certificate")]
	#[deprecated]
	pub __certificate:        Option<serde::de::IgnoredAny>,
	#[serde(default, skip_serializing, rename = "private_key")]
	#[deprecated]
	pub __private_key:        Option<serde::de::IgnoredAny>,
	#[serde(default, skip_serializing, rename = "congestion_control")]
	#[deprecated]
	pub __congestion_control: Option<IgnoredAny>,
	#[serde(default, rename = "alpn")]
	#[deprecated]
	pub __alpn:               Option<Vec<String>>,
	#[serde(default, rename = "max_idle_time", with = "humantime_serde")]
	#[deprecated]
	pub __max_idle_time:      Option<Duration>,
	#[serde(default, skip_serializing, rename = "initial_window")]
	#[deprecated]
	pub __initial_window:     Option<IgnoredAny>,
	#[serde(default, rename = "receive_window")]
	#[deprecated]
	pub __send_window:        Option<u64>,
	#[serde(default, rename = "send_window")]
	#[deprecated]
	pub __receive_window:     Option<u32>,
	#[serde(default, rename = "initial_mtu")]
	#[deprecated]
	pub __initial_mtu:        Option<u16>,
	#[serde(default, rename = "min_mtu")]
	#[deprecated]
	pub __min_mtu:            Option<u16>,
	#[serde(default, rename = "gso")]
	#[deprecated]
	pub __gso:                Option<bool>,
	#[serde(default, rename = "pmtu")]
	#[deprecated]
	pub __pmtu:               Option<bool>,
}


#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct QuicConfig {
	/// Old congestion_control section (deprecated, now fetched from panel API)
	#[serde(default, skip_serializing, rename = "congestion_control")]
	#[deprecated]
	pub __congestion_control: Option<IgnoredAny>,

	#[educe(Default = 1048576)]
	pub initial_window: u64,

	#[educe(Default = 1200)]
	pub initial_mtu: u16,

	#[educe(Default = 1200)]
	pub min_mtu: u16,

	#[educe(Default = true)]
	pub gso: bool,

	#[educe(Default = true)]
	pub pmtu: bool,

	#[educe(Default = 16777216)]
	pub send_window: u64,

	#[educe(Default = 8388608)]
	pub receive_window: u32,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(30)))]
	pub max_idle_time: Duration,
}

#[derive(Deserialize, Serialize, Educe, Clone)]
#[educe(Default)]
#[serde(default)]
pub struct ExperimentalConfig {
	#[educe(Default = true)]
	pub drop_loopback: bool,
	#[educe(Default = true)]
	pub drop_private:  bool,
}

impl ExperimentalConfig {
	const DEFAULT_CONCURRENT_STREAMS: u32 = 32;

	pub fn max_concurrent_uni_streams(&self) -> u32 {
		Self::DEFAULT_CONCURRENT_STREAMS
	}

	pub fn max_concurrent_bidi_streams(&self) -> u32 {
		Self::DEFAULT_CONCURRENT_STREAMS
	}
}

impl Config {
	pub fn migrate(&mut self) {
		// Migrate QUIC-related fields (congestion_control and initial_window are now
		// from API)
		#[allow(deprecated)]
		{
			if let Some(max_idle_time) = self.__max_idle_time {
				self.quic.max_idle_time = max_idle_time;
			}
			if let Some(send_window) = self.__send_window {
				self.quic.send_window = send_window;
			}
			if let Some(receive_window) = self.__receive_window {
				self.quic.receive_window = receive_window;
			}
			if let Some(initial_mtu) = self.__initial_mtu {
				self.quic.initial_mtu = initial_mtu;
			}
			if let Some(min_mtu) = self.__min_mtu {
				self.quic.min_mtu = min_mtu;
			}
			if let Some(gso) = self.__gso {
				self.quic.gso = gso;
			}
			if let Some(pmtu) = self.__pmtu {
				self.quic.pmtu = pmtu;
			}
		}
	}
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, ValueEnum)]
#[serde(rename_all = "lowercase")]
#[derive(Educe)]
#[educe(Default)]
pub enum LogLevel {
	Trace,
	Debug,
	#[educe(Default)]
	Info,
	Warn,
	Error,
	Off,
}
impl From<LogLevel> for LevelFilter {
	fn from(value: LogLevel) -> Self {
		match value {
			LogLevel::Trace => LevelFilter::TRACE,
			LogLevel::Debug => LevelFilter::DEBUG,
			LogLevel::Info => LevelFilter::INFO,
			LogLevel::Warn => LevelFilter::WARN,
			LogLevel::Error => LevelFilter::ERROR,
			LogLevel::Off => LevelFilter::OFF,
		}
	}
}


pub async fn parse_config(cli: Cli) -> eyre::Result<Config> {
	// Handle --init flag
	if cli.init {
		tokio::fs::write("config.toml.example", include_bytes!("../examples/config.toml.example")).await?;
		tokio::fs::write("acl.yaml.example", include_bytes!("../examples/acl.yaml.example")).await?;
		warn!("Generated: config.toml.example, acl.yaml.example");
		return Err(Control("Done").into());
	}

	// Start with default config
	let mut figment = Figment::from(Serialized::defaults(Config::default()));

	// Merge external config file if provided
	if let Some(cfg_path) = &cli.ext_conf_file {
		if !cfg_path.exists() {
			return Err(eyre::eyre!("Config file not found: {}", cfg_path.display()));
		}
		// Validate file extension before parsing
		let ext = cfg_path.extension().and_then(|e| e.to_str()).unwrap_or("");
		if !ext.eq_ignore_ascii_case("toml") {
			return Err(eyre::eyre!(
				"Invalid config file format: expected .toml extension, got .{} (file: {})",
				ext,
				cfg_path.display()
			));
		}
		figment = figment.merge(Toml::file(cfg_path));
	}

	let mut config: Config = figment.extract()?;

	// Migrate legacy fields to new nested structure
	config.migrate();

	// Parse ACL config if provided
	if let Some(acl_path) = &cli.acl_conf_file {
		if !acl_path.exists() {
			return Err(eyre::eyre!("ACL config file not found: {}", acl_path.display()));
		}
		// Validate file extension before parsing
		let ext = acl_path.extension().and_then(|e| e.to_str()).unwrap_or("");
		if !ext.eq_ignore_ascii_case("yaml") && !ext.eq_ignore_ascii_case("yml") {
			return Err(eyre::eyre!(
				"Invalid ACL config file format: expected .yaml or .yml extension, got .{} (file: {})",
				ext,
				acl_path.display()
			));
		}
		let yaml_content = tokio::fs::read_to_string(acl_path).await?;
		let acl_config: crate::acl::AclConfig = serde_yaml::from_str(&yaml_content)?;
		let acl_engine = crate::acl::AclEngine::new(acl_config, &cli.data_dir, cli.refresh_geodata).await?;
		config.acl_engine = Some(std::sync::Arc::new(acl_engine));
	} else {
		// No ACL config provided, create default engine
		let default_engine = crate::acl::create_default_engine(&cli.data_dir, cli.refresh_geodata).await?;
		config.acl_engine = Some(std::sync::Arc::new(default_engine));
	}

	// Set CLI arguments into config
	config.log_mode = cli.log_mode;
	config.cert_file = cli.cert_file;
	config.key_file = cli.key_file;

	// Check if node_id is required (not in init mode)
	let node_id = cli
		.node
		.ok_or_else(|| eyre::eyre!("--node <ID> is required when not using --init"))?;

	// Set panel configuration (required fields)
	let server_name = cli.server_name.unwrap_or_else(|| cli.host.clone());
	config.panel = Some(crate::panel::PanelConfig {
		server_host: cli.host,
		server_port: cli.port,
		node_id,
		fetch_users_interval: cli.fetch_users_interval,
		report_traffics_interval: cli.report_traffics_interval,
		heartbeat_interval: cli.heartbeat_interval,
		data_dir: cli.data_dir,
		request_timeout: cli.request_timeout,
		server_name,
		ca_cert_path: cli.ca_cert,
		ip_version: cli.panel_ip_version,
	});

	Ok(config)
}

#[cfg(test)]
mod tests {
	use std::fs;

	use tempfile::tempdir;

	use super::*;

	async fn test_parse_config(config_content: &str) -> eyre::Result<Config> {
		let temp_dir = tempdir().unwrap();
		let config_path = temp_dir.path().join("config.toml");

		fs::write(&config_path, config_content).unwrap();

		// Temporarily set command line arguments for clap to parse
		let os_args = vec![
			"test_binary".to_owned(),
			"--ext_conf_file".to_owned(),
			config_path.to_string_lossy().into_owned(),
			"--node".to_owned(),
			"1".to_owned(),
		];

		// Parse CLI with test arguments
		let cli = Cli::try_parse_from(os_args)?;

		// Call parse_config with the CLI
		parse_config(cli).await
	}
	#[tokio::test]
	async fn test_valid_toml_config() -> eyre::Result<()> {
		let config = include_str!("../tests/config/valid_toml_config.toml");

		let result = test_parse_config(config).await.unwrap();

		// server and zero_rtt_handshake fields are now deprecated, fetched from panel
		// API
		assert!(!result.udp_relay_ipv6);
		// zero_rtt_handshake defaults to false, set by panel API
		assert!(!result.zero_rtt_handshake);

		assert_eq!(result.quic.initial_mtu, 1400);
		assert_eq!(result.quic.min_mtu, 1300);
		assert_eq!(result.quic.send_window, 10000000);
		// congestion_control is now from API, not config file
		assert_eq!(result.congestion_control, CongestionController::Bbr);

		// Users are now fetched from panel API, not config file
		// The users field in config is deprecated and ignored

		Ok(())
	}

	#[tokio::test]
	async fn test_error_handling() {
		// Test Invalid TOML
		let config = "invalid toml content";
		let result = test_parse_config(config).await;
		assert!(result.is_err());

		// Test non-existent configuration files - should fail when trying to parse
		let result = Cli::try_parse_from(vec!["test_binary", "--ext_conf_file", "non_existent.toml", "--node", "1"]);
		// This will succeed at parsing CLI level, but fail when actually loading the
		// file
		if let Ok(cli) = result {
			assert!(cli.ext_conf_file.is_some());
			assert!(!cli.ext_conf_file.unwrap().exists());
		}

		// Test missing required parameters - CLI parsing succeeds (node is optional)
		// but config parsing should fail if not in --init mode
		let result = Cli::try_parse_from(vec!["test_binary"]);
		// This should succeed at CLI level now since --node is optional
		assert!(result.is_ok());
		let cli = result.unwrap();
		assert!(cli.node.is_none());
		assert!(!cli.init);
	}

	#[tokio::test]
	async fn test_default_values() {
		// Test minimal configuration with defaults
		let config = include_str!("../tests/config/default_values.toml");

		let result = test_parse_config(config).await.unwrap();

		// Check default values
		// server_port and zero_rtt_handshake are fetched from panel API, default to
		// 0/false
		assert_eq!(result.server_port, 0);
		assert!(result.udp_relay_ipv6);
		assert!(!result.zero_rtt_handshake); // defaults to false, set by panel API
		assert!(result.dual_stack);
		assert_eq!(result.auth_timeout, Duration::from_secs(3));
		assert_eq!(result.task_negotiation_timeout, Duration::from_secs(3));
		assert_eq!(result.gc_interval, Duration::from_secs(10));
		assert_eq!(result.gc_lifetime, Duration::from_secs(30));
		assert_eq!(result.max_external_packet_size, 1500);
		assert_eq!(result.stream_timeout, Duration::from_secs(60));
	}
	#[tokio::test]
	async fn test_invalid_uuid() {
		// Users are now fetched from panel API, not config file
		// The users field is deprecated and ignored, so invalid UUIDs don't cause
		// errors
		let config = include_str!("../tests/config/invalid_uuid.toml");

		let result = test_parse_config(config).await;
		// Should succeed now since users field is ignored
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_invalid_socket_addr() {
		// server field is now deprecated and ignored, so invalid addresses don't cause
		// errors The server_port is fetched from panel API instead
		let config = include_str!("../tests/config/invalid_socket_addr.toml");

		let result = test_parse_config(config).await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_duration_parsing() {
		let config = include_str!("../tests/config/duration_parsing.toml");

		let result = test_parse_config(config).await.unwrap();

		assert_eq!(result.auth_timeout, Duration::from_secs(5));
		assert_eq!(result.task_negotiation_timeout, Duration::from_secs(10));
		assert_eq!(result.gc_interval, Duration::from_secs(30));
		assert_eq!(result.gc_lifetime, Duration::from_secs(60));
		assert_eq!(result.stream_timeout, Duration::from_secs(120));
	}


	#[tokio::test]
	async fn test_congestion_control_in_config_file_ignored() {
		// congestion_control in config file is now ignored (fetched from API)
		let config_bbr = include_str!("../tests/config/congestion_control_bbr.toml");
		let result = test_parse_config(config_bbr).await.unwrap();
		// Default value since config file congestion_control is ignored
		assert_eq!(result.congestion_control, CongestionController::Bbr);

		let config_new_reno = include_str!("../tests/config/congestion_control_newreno.toml");
		let result = test_parse_config(config_new_reno).await.unwrap();
		// Still default since config file value is ignored
		assert_eq!(result.congestion_control, CongestionController::Bbr);
	}
}
