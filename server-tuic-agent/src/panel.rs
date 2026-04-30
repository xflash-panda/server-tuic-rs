use std::{path::PathBuf, sync::Arc, time::Duration};

use panel_connect_rpc::{ConnectRpcApiManager, ConnectRpcPanelConfig, IpVersion};
use panel_core::{BackgroundTasks, BackgroundTasksHandle, NodeConfigEnum, PanelApi, StatsCollector, TaskConfig, UserManager};
use server_client_rs::models::TuicConfig;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{AppContext, utils::CongestionController};

/// Derive key function for TUIC: parse UUID string into Uuid.
/// Invalid UUIDs map to Uuid::nil() (will never match a real auth attempt).
fn tuic_derive_key(uuid_str: &str) -> Uuid {
	Uuid::parse_str(uuid_str).unwrap_or_else(|e| {
		warn!("Invalid UUID format '{}': {}", uuid_str, e);
		Uuid::nil()
	})
}

/// Configuration for the panel service
#[derive(Debug, Clone)]
pub struct PanelConfig {
	/// Panel server host (e.g., "127.0.0.1")
	pub server_host:              String,
	/// Panel server port (e.g., 8082)
	pub server_port:              u16,
	/// Node ID for this server
	pub node_id:                  u32,
	/// Interval for fetching users from API (in seconds)
	pub fetch_users_interval:     u64,
	/// Interval for reporting traffic stats to API (in seconds)
	pub report_traffics_interval: u64,
	/// Interval for sending heartbeat to API (in seconds)
	pub heartbeat_interval:       u64,
	/// Data directory for persisting state and other data
	pub data_dir:                 PathBuf,
	/// Request timeout in seconds (default: 15)
	pub request_timeout:          u64,
	/// TLS server name (SNI) for panel connection
	pub server_name:              String,
	/// CA certificate path (None = use system trust store)
	pub ca_cert_path:             Option<String>,
	/// IP version preference for outbound connections (default: Auto)
	pub ip_version:               IpVersion,
}

/// Panel service implementation backed by server-panel-rs (ConnectRPC
/// transport)
pub struct Panel {
	api:             Arc<ConnectRpcApiManager>,
	config:          PanelConfig,
	user_manager:    Arc<UserManager<Uuid>>,
	stats_collector: Arc<StatsCollector>,
}

impl Panel {
	/// Create a new Panel instance
	pub fn new(config: PanelConfig) -> eyre::Result<Self> {
		let rpc_config = ConnectRpcPanelConfig {
			server_host:  config.server_host.clone(),
			server_port:  config.server_port,
			node_id:      config.node_id,
			node_type:    panel_core::NodeType::Tuic,
			data_dir:     config.data_dir.clone(),
			api_timeout:  Duration::from_secs(config.request_timeout),
			server_name:  config.server_name.clone(),
			ca_cert_path: config.ca_cert_path.clone(),
			ip_version:   config.ip_version,
		};

		let api = Arc::new(ConnectRpcApiManager::new(rpc_config));
		let user_manager = Arc::new(UserManager::new(tuic_derive_key));
		let stats_collector = Arc::new(StatsCollector::new());

		Ok(Self {
			api,
			config,
			user_manager,
			stats_collector,
		})
	}

	/// Get a reference to the StatsCollector
	pub fn stats_collector(&self) -> &Arc<StatsCollector> {
		&self.stats_collector
	}

	/// Validate a user by UUID, returns the user_id if valid.
	/// Lock-free via ArcSwap — no async needed.
	pub fn validate_user(&self, uuid: &Uuid) -> Option<i64> {
		self.user_manager.authenticate(uuid)
	}

	/// Get all user IDs (for traffic stats initialization)
	pub fn get_all_user_ids(&self) -> Vec<i64> {
		self.user_manager.get_users().values().copied().collect()
	}

	/// Initialize the panel: fetch config, register, fetch users
	pub async fn init(&self, cfg: &mut crate::Config) -> eyre::Result<()> {
		info!("Panel service initializing...");

		// Ensure data directory exists
		if !self.config.data_dir.exists() {
			info!("Creating data directory: {:?}", self.config.data_dir);
			std::fs::create_dir_all(&self.config.data_dir).map_err(|e| {
				error!("Failed to create data directory: {}", e);
				eyre::eyre!("Failed to create data directory {:?}: {}", self.config.data_dir, e)
			})?;
		}

		// Fetch config from panel
		let node_config = self
			.api
			.fetch_config()
			.await
			.map_err(|e| eyre::eyre!("Failed to fetch config from server: {}", e))?;

		let tuic_config: TuicConfig = match node_config {
			NodeConfigEnum::Tuic(json) => {
				serde_json::from_str(&json).map_err(|e| eyre::eyre!("Failed to parse TuicConfig: {}", e))?
			}
			other => {
				return Err(eyre::eyre!("Expected Tuic config, got: {:?}", other));
			}
		};

		info!("Successfully fetched node config: {:?}", tuic_config);

		let server_port = tuic_config.server_port;
		let zero_rtt_handshake = tuic_config.zero_rtt_handshake;
		let server_name = tuic_config.server_name.clone();
		let mut congestion_control = CongestionController::default();
		if let Some(cc_str) = &tuic_config.server_congestion_control {
			match cc_str.parse::<CongestionController>() {
				Ok(cc) => congestion_control = cc,
				Err(_) => warn!(
					"Unknown congestion control '{}' from API, using default: {:?}",
					cc_str, congestion_control
				),
			}
		}

		info!(
			"Tuic config - server_port: {}, zero_rtt_handshake: {}, congestion_control: {:?}, id: {}, server_name: {:?}",
			server_port, zero_rtt_handshake, congestion_control, tuic_config.id, server_name
		);

		// Update config with values from panel API
		cfg.server_port = server_port;
		cfg.zero_rtt_handshake = zero_rtt_handshake;
		cfg.congestion_control = congestion_control;
		cfg.server_name = server_name;

		// Initialize (register node)
		self.api
			.initialize(server_port)
			.await
			.map_err(|e| eyre::eyre!("Failed to register node: {}", e))?;

		info!("Node registered successfully");

		// Fetch initial users
		if let Some(users) = self
			.api
			.fetch_users()
			.await
			.map_err(|e| eyre::eyre!("Failed to fetch users: {}", e))?
		{
			self.user_manager.init(&users);
			info!("Fetched {} initial users", users.len());
		}

		// Send initial heartbeat
		self.api
			.heartbeat()
			.await
			.map_err(|e| eyre::eyre!("Failed to send heartbeat: {}", e))?;

		info!("Panel service initialized, server_port: {}", server_port);
		Ok(())
	}

	/// Start background tasks (fetch users, heartbeat, submit traffic).
	/// BackgroundTasks creates its own dedicated runtime internally.
	pub fn start_background_tasks(&self, ctx: Arc<AppContext>) -> BackgroundTasksHandle {
		let task_config = TaskConfig::new(
			Duration::from_secs(self.config.fetch_users_interval),
			Duration::from_secs(self.config.report_traffics_interval),
			Duration::from_secs(self.config.heartbeat_interval),
		);

		BackgroundTasks::new(
			task_config,
			self.api.clone(),
			self.user_manager.clone(),
			self.stats_collector.clone(),
		)
		.on_user_diff(Arc::new(move |diff| {
			let ctx = ctx.clone();
			tokio::spawn(async move {
				let mut ids_to_kick = diff.removed_ids;
				ids_to_kick.extend(diff.uuid_changed_ids);
				if !ids_to_kick.is_empty() {
					info!("Kicking {} user(s) (removed/uuid-changed)", ids_to_kick.len());
					ctx.kick_users(&ids_to_kick).await;
				}
			});
		}))
		.start()
	}

	/// Close the panel service (unregister node)
	pub async fn close(&self) -> eyre::Result<()> {
		info!("Panel service closing...");

		match self.api.unregister().await {
			Ok(()) => {
				info!("Node unregistered successfully");
			}
			Err(e) => {
				warn!("Failed to unregister node: {}", e);
			}
		}

		info!("Panel service closed");
		Ok(())
	}
}

/// Optional panel service wrapper for when panel is not configured
pub struct OptionalPanel {
	inner: Option<Arc<Panel>>,
}

impl OptionalPanel {
	/// Create with a panel service
	pub fn with_panel(panel: Panel) -> Self {
		Self {
			inner: Some(Arc::new(panel)),
		}
	}

	/// Create without a panel service (disabled)
	pub fn disabled() -> Self {
		Self { inner: None }
	}

	/// Check if panel is enabled
	pub fn is_enabled(&self) -> bool {
		self.inner.is_some()
	}

	/// Get a reference to the inner panel if enabled
	pub fn panel(&self) -> Option<&Arc<Panel>> {
		self.inner.as_ref()
	}

	/// Validate a user by UUID, returns the user_id if valid
	/// Returns None if panel is disabled or user is not found
	pub fn validate_user(&self, uuid: &Uuid) -> Option<i64> {
		if let Some(panel) = &self.inner {
			panel.validate_user(uuid)
		} else {
			None
		}
	}

	/// Get all user IDs (for traffic stats initialization)
	/// Returns empty vec if panel is disabled
	pub fn get_all_user_ids(&self) -> Vec<i64> {
		if let Some(panel) = &self.inner {
			panel.get_all_user_ids()
		} else {
			Vec::new()
		}
	}

	/// Get the StatsCollector if panel is enabled
	pub fn stats_collector(&self) -> Option<&Arc<StatsCollector>> {
		self.inner.as_ref().map(|p| p.stats_collector())
	}

	/// Initialize the panel service
	pub async fn init(&self, cfg: &mut crate::Config) -> eyre::Result<()> {
		if let Some(panel) = &self.inner {
			panel.init(cfg).await
		} else {
			error!("Panel service is required but not configured");
			Err(eyre::eyre!("Panel service is required to get server_port from API"))
		}
	}

	/// Start background tasks
	pub fn start_background_tasks(&self, ctx: Arc<AppContext>) -> Option<BackgroundTasksHandle> {
		self.inner.as_ref().map(|panel| panel.start_background_tasks(ctx))
	}

	/// Close the panel service
	pub async fn close(&self) -> eyre::Result<()> {
		if let Some(panel) = &self.inner {
			panel.close().await
		} else {
			warn!("Panel service is disabled, skipping close");
			Ok(())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_optional_panel_disabled() {
		let panel = OptionalPanel::disabled();
		assert!(!panel.is_enabled());
		assert!(panel.panel().is_none());
		assert!(panel.stats_collector().is_none());
	}

	#[test]
	fn test_optional_panel_disabled_validate_user() {
		let panel = OptionalPanel::disabled();
		let uuid = Uuid::new_v4();
		assert_eq!(panel.validate_user(&uuid), None);
	}

	#[test]
	fn test_optional_panel_disabled_get_all_user_ids() {
		let panel = OptionalPanel::disabled();
		assert!(panel.get_all_user_ids().is_empty());
	}
}
