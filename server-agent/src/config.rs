use std::{path::PathBuf, time::Duration};

use clap::{Parser, ValueEnum};
use educe::Educe;
use figment::{
	Figment,
	providers::{Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};
use tracing::{level_filters::LevelFilter, warn};

use crate::utils::CongestionController;


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

	/// gRPC server host (e.g., "127.0.0.1")
	#[arg(long = "server_host", value_name = "HOST", default_value = "127.0.0.1")]
	pub host: String,

	/// gRPC server port (e.g., 8082)
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

	/// gRPC request timeout (in seconds)
	#[arg(long = "timeout", value_name = "SECONDS", default_value = "15")]
	pub request_timeout: u64,
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

	/// Zero RTT handshake (set from panel API during init)
	#[serde(skip)]
	pub zero_rtt_handshake: bool,

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
	#[serde(default, rename = "congestion_control")]
	#[deprecated]
	pub __congestion_control: Option<CongestionController>,
	#[serde(default, rename = "alpn")]
	#[deprecated]
	pub __alpn:               Option<Vec<String>>,
	#[serde(default, rename = "max_idle_time", with = "humantime_serde")]
	#[deprecated]
	pub __max_idle_time:      Option<Duration>,
	#[serde(default, rename = "initial_window")]
	#[deprecated]
	pub __initial_window:     Option<u64>,
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
	pub congestion_control: CongestionControlConfig,

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

#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct CongestionControlConfig {
	pub controller:     CongestionController,
	#[educe(Default = 1048576)]
	pub initial_window: u64,
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

impl Config {
	pub fn migrate(&mut self) {
		// Migrate QUIC-related fields
		#[allow(deprecated)]
		{
			if let Some(congestion_control) = self.__congestion_control {
				self.quic.congestion_control.controller = congestion_control;
			}
			if let Some(max_idle_time) = self.__max_idle_time {
				self.quic.max_idle_time = max_idle_time;
			}
			if let Some(initial_window) = self.__initial_window {
				self.quic.congestion_control.initial_window = initial_window;
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
		warn!("Generating example configuration files......");

		// Generate TOML configuration file example
		let toml_config = r#"# TUIC Server 配置文件示例
# 此文件定义服务器的基础配置参数
# 重命名为 config.toml 并通过 --ext_conf_file 参数使用

# ============================================
# 基础配置
# ============================================

# UDP 配置
udp_relay_ipv6 = true          # 为 IPv6 UDP 创建单独套接字
dual_stack = true              # 启用双栈 (IPv4/IPv6)

# 超时配置
auth_timeout = "3s"            # 客户端认证超时
task_negotiation_timeout = "3s" # 任务协商超时
gc_interval = "10s"            # UDP 片段垃圾回收间隔
gc_lifetime = "30s"            # UDP 片段保留时间
stream_timeout = "60s"         # 流超时

# 数据包配置
max_external_packet_size = 1500 # 外部 UDP 数据包最大大小

# ============================================
# QUIC 配置
# ============================================

[quic]
initial_mtu = 1200             # 初始 MTU
min_mtu = 1200                 # 最小 MTU (至少 1200)
gso = true                     # 启用通用分段卸载
pmtu = true                    # 启用路径 MTU 发现
send_window = 16777216         # 发送窗口大小 (字节)
receive_window = 8388608       # 接收窗口大小 (字节)
max_idle_time = "30s"          # 空闲连接超时

# 拥塞控制配置
[quic.congestion_control]
controller = "bbr"             # 拥塞控制算法: bbr / cubic / new_reno
initial_window = 1048576       # 初始拥塞窗口 (字节)

# ============================================
# 实验性功能
# ============================================

[experimental]
drop_loopback = true           # 禁止连接到环回地址 (127.0.0.1, ::1) - 默认启用
drop_private = true            # 禁止连接到私有地址 - 默认启用

# 注意:
# - server_port 和 zero_rtt_handshake 从控制面板 API 动态获取
# - 大部分用户不需要修改这些配置，默认值已经过优化
# - 路由配置请使用 ACL 配置文件 (acl.yaml)
# - 如需允许连接到私有地址/环回地址，请将上述配置设为 false
"#;

		tokio::fs::write("config.toml.example", toml_config).await?;
		warn!("Generated config.toml.example (TUIC server configuration)");

		// Generate default ACL configuration with comments
		let default_acl_config = r#"# ACL 配置文件
# 此文件定义了流量路由规则

# 定义出站连接类型
outbounds:
  # 直连出站（默认）
  - name: default
    type: direct
    direct:
      mode: auto  # 选项: auto (自动), 4 (仅 IPv4), 6 (仅 IPv6)

  # SOCKS5 代理出站（示例，默认禁用）
  # 取消注释以启用 SOCKS5 代理
  # - name: proxy
  #   type: socks5
  #   socks5:
  #     addr: 127.0.0.1:1080
  #     username: user  # 可选，如需认证请填写
  #     password: pass  # 可选，如需认证请填写
  #     allow_udp: false

# ACL 路由规则（按顺序匹配，首次匹配生效）
acl:
  inline:
    # 默认规则：所有流量直连
    # 这是无配置文件时的默认行为
    - default(all)

    # 更多规则示例（取消注释以启用）:

    # 阻止 QUIC 协议（防止协议检测）
    # - reject(all, udp/443)

    # 阻止 SMTP 端口
    # - reject(all, tcp/25)
    # - reject(all, tcp/465)
    # - reject(all, tcp/587)

    # 通过代理路由特定域名
    # - proxy(suffix:google.com)
    # - proxy(suffix:youtube.com)
    # - proxy(geosite:openai)
    # - proxy(geosite:netflix)

    # 私有网络直连
    # - default(192.168.0.0/16)
    # - default(10.0.0.0/8)
    # - default(172.16.0.0/12)

    # 中国大陆 IP 直连（需要 GeoIP 数据库）
    # - default(geoip:cn)

    # 特定域名走代理，仅 HTTPS
    # - proxy(example.com, tcp/443)

# 规则语法说明:
#
# 格式: outbound_name(matcher[, protocol/port])
#
# 地址匹配器:
#   all 或 *              匹配所有地址
#   1.2.3.4              单个 IP 地址
#   192.168.0.0/16       CIDR 网段
#   example.com          精确域名匹配
#   *.example.com        通配符域名
#   suffix:example.com   后缀匹配
#   geoip:cn             GeoIP 国家代码
#   geosite:google       GeoSite 分类
#
# 协议/端口过滤 (可选):
#   tcp/80               TCP 端口 80
#   udp/443              UDP 端口 443
#   tcp/80-443           TCP 端口范围
#   tcp                  所有 TCP
#   udp                  所有 UDP
#
# 注意:
#   - 规则按顺序匹配，首次匹配的规则生效
#   - 最后一条规则应该是兜底规则（如 default(all)）
#   - reject 类型会直接丢弃连接
#   - GeoIP/GeoSite 功能需要配置相应的数据库文件
"#;

		tokio::fs::write("acl.yaml.example", default_acl_config).await?;
		warn!("Generated acl.yaml.example (ACL routing configuration)");
		warn!("");
		warn!("Configuration files generated:");
		warn!("  - config.toml.example: TUIC server configuration");
		warn!("  - acl.yaml.example:    ACL routing rules");
		warn!("");
		warn!("To use:");
		warn!("  1. Copy and rename: cp config.toml.example config.toml");
		warn!("  2. Copy and rename: cp acl.yaml.example acl.yaml");
		warn!("  3. Edit the files as needed");
		warn!("  4. Run: tuic-server --node <ID> --ext_conf_file config.toml --acl_conf_file acl.yaml");
		warn!("");
		warn!("Or use default configuration (zero-config):");
		warn!("  tuic-server --node <ID>");
		return Err(Control("Done").into());
	}

	// Start with default config
	let mut figment = Figment::from(Serialized::defaults(Config::default()));

	// Merge external config file if provided
	if let Some(cfg_path) = &cli.ext_conf_file {
		if !cfg_path.exists() {
			return Err(eyre::eyre!("Config file not found: {}", cfg_path.display()));
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
		let yaml_content = tokio::fs::read_to_string(acl_path).await?;
		let acl_config: crate::acl::AclConfig = serde_yaml::from_str(&yaml_content)?;
		let acl_engine = crate::acl::AclEngine::new(acl_config).await?;
		config.acl_engine = Some(std::sync::Arc::new(acl_engine));
	} else {
		// No ACL config provided, create default engine
		let default_engine = crate::acl::create_default_engine().await?;
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
	config.panel = Some(crate::panel::PanelConfig {
		server_host: cli.host,
		server_port: cli.port,
		node_id,
		fetch_users_interval: cli.fetch_users_interval,
		report_traffics_interval: cli.report_traffics_interval,
		heartbeat_interval: cli.heartbeat_interval,
		data_dir: cli.data_dir,
		request_timeout: cli.request_timeout,
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
		assert_eq!(result.quic.congestion_control.controller, CongestionController::Bbr);
		assert_eq!(result.quic.congestion_control.initial_window, 2000000);

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
	async fn test_congestion_control_variants() {
		// Test BBR
		let config_bbr = include_str!("../tests/config/congestion_control_bbr.toml");

		let result = test_parse_config(config_bbr).await.unwrap();
		assert_eq!(result.quic.congestion_control.controller, CongestionController::Bbr);

		// Test NewReno (note: lowercase 'newreno' is the valid variant)
		let config_new_reno = include_str!("../tests/config/congestion_control_newreno.toml");

		let result = test_parse_config(config_new_reno).await.unwrap();
		assert_eq!(result.quic.congestion_control.controller, CongestionController::NewReno);
	}
}
