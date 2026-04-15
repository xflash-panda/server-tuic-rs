use std::{collections::HashMap, collections::HashSet, path::PathBuf, sync::Arc, time::Duration};

use panel_connect_rpc::{ConnectRpcApiManager, ConnectRpcPanelConfig};
use panel_core::{
	BackgroundTasks, BackgroundTasksHandle, NodeConfigEnum, PanelApi, StatsCollector, TaskConfig, User, UserManager,
};
use server_client_rs::models::TuicConfig;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{AppContext, utils::CongestionController};

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
}

/// User map: UUID -> user_id (i64), maintained separately for TUIC's UUID-based auth
type UserMap = HashMap<Uuid, i64>;

/// Wrapper around ConnectRpcApiManager that intercepts fetch_users()
/// to also update the TUIC-specific UUID -> user_id map.
///
/// Key ordering: on fetch_users(), we compute which UUIDs will be kicked
/// (removed/uuid-changed) BEFORE rebuilding the UUID map, then store them
/// in `pending_kicks` for the on_user_diff callback to consume.
struct TuicPanelApi {
	inner: ConnectRpcApiManager,
	/// Shared UUID map updated on every user fetch
	users: Arc<RwLock<UserMap>>,
	/// UUIDs that should be kicked after the next user diff.
	/// Computed during fetch_users() while old UUID map is still available.
	pending_kicks: Arc<RwLock<Vec<Uuid>>>,
}

#[async_trait::async_trait]
impl PanelApi for TuicPanelApi {
	async fn initialize(&self, port: u16) -> anyhow::Result<()> {
		self.inner.initialize(port).await
	}

	async fn fetch_users(&self) -> anyhow::Result<Option<Vec<User>>> {
		let result = self.inner.fetch_users().await?;
		if let Some(ref new_users) = result {
			// Compute UUIDs to kick BEFORE rebuilding the map.
			// After rebuild, removed users' UUIDs are gone from the map.
			let kicks = {
				let old_map = self.users.read().await;
				compute_kicks(&old_map, new_users)
			};

			*self.pending_kicks.write().await = kicks;

			// Now rebuild the UUID map with new users
			rebuild_uuid_map(&self.users, new_users).await;
		}
		Ok(result)
	}

	async fn submit_traffic(&self, data: Vec<panel_core::UserTraffic>) -> anyhow::Result<()> {
		self.inner.submit_traffic(data).await
	}

	async fn heartbeat(&self) -> anyhow::Result<()> {
		self.inner.heartbeat().await
	}

	async fn unregister(&self) -> anyhow::Result<()> {
		self.inner.unregister().await
	}

	async fn fetch_config(&self) -> anyhow::Result<NodeConfigEnum> {
		self.inner.fetch_config().await
	}
}

/// Panel service implementation backed by server-panel-rs
pub struct Panel {
	api:             Arc<TuicPanelApi>,
	config:          PanelConfig,
	user_manager:    Arc<UserManager>,
	stats_collector: Arc<StatsCollector>,
	/// UUID -> user_id mapping for TUIC UUID-based authentication
	users:           Arc<RwLock<UserMap>>,
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
		};

		let users: Arc<RwLock<UserMap>> = Arc::new(RwLock::new(HashMap::new()));

		let pending_kicks: Arc<RwLock<Vec<Uuid>>> = Arc::new(RwLock::new(Vec::new()));

		let api = Arc::new(TuicPanelApi {
			inner: ConnectRpcApiManager::new(rpc_config),
			users: users.clone(),
			pending_kicks: pending_kicks.clone(),
		});
		let user_manager = Arc::new(UserManager::new());
		let stats_collector = Arc::new(StatsCollector::new());

		Ok(Self {
			api,
			config,
			user_manager,
			stats_collector,
			users,
		})
	}

	/// Get a reference to the StatsCollector
	pub fn stats_collector(&self) -> &Arc<StatsCollector> {
		&self.stats_collector
	}

	/// Validate a user by UUID, returns the user_id if valid
	pub async fn validate_user(&self, uuid: &Uuid) -> Option<i64> {
		self.users.read().await.get(uuid).copied()
	}

	/// Get all user IDs (for traffic stats initialization)
	pub async fn get_all_user_ids(&self) -> Vec<i64> {
		self.users.read().await.values().copied().collect()
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

		// Fetch initial users (this also updates the UUID map via TuicPanelApi wrapper)
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

		let pending_kicks = self.api.pending_kicks.clone();

		BackgroundTasks::new(
			task_config,
			self.api.clone(),
			self.user_manager.clone(),
			self.stats_collector.clone(),
		)
		.on_user_diff(Arc::new(move |_diff| {
			// Consume pending_kicks computed during fetch_users()
			// (before the UUID map was rebuilt, so old UUIDs are captured)
			let ctx = ctx.clone();
			let pending_kicks = pending_kicks.clone();

			tokio::spawn(async move {
				let uuids_to_kick: Vec<Uuid> = std::mem::take(&mut *pending_kicks.write().await);
				if !uuids_to_kick.is_empty() {
					info!("Kicking {} user(s) with stale UUIDs", uuids_to_kick.len());
					ctx.kick_users(&uuids_to_kick).await;
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

/// Compute which UUIDs should be kicked based on the old UUID map and new user list.
///
/// A UUID is kicked when:
/// - The user_id no longer exists in the new user list (user removed)
/// - The user_id exists but its UUID has changed (UUID rotation)
fn compute_kicks(old_map: &UserMap, new_users: &[User]) -> Vec<Uuid> {
	let new_ids: HashSet<i64> = new_users.iter().map(|u| u.id).collect();
	let new_uuid_by_id: HashMap<i64, &str> = new_users.iter().map(|u| (u.id, u.uuid.as_str())).collect();

	let mut kicks = Vec::new();
	for (uuid, uid) in old_map.iter() {
		if !new_ids.contains(uid) {
			// User removed
			kicks.push(*uuid);
		} else if let Some(new_uuid_str) = new_uuid_by_id.get(uid) {
			// User exists but UUID may have changed
			if let Ok(new_uuid) = Uuid::parse_str(new_uuid_str) {
				if &new_uuid != uuid {
					kicks.push(*uuid);
				}
			}
		}
	}
	kicks
}

/// Rebuild the UUID -> user_id map from a list of users
async fn rebuild_uuid_map(users_lock: &RwLock<UserMap>, users: &[User]) {
	let mut user_map = users_lock.write().await;
	user_map.clear();
	for user in users {
		if let Ok(uuid) = Uuid::parse_str(&user.uuid) {
			user_map.insert(uuid, user.id);
		} else {
			warn!("Invalid UUID format for user {}: {}", user.id, user.uuid);
		}
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
	pub async fn validate_user(&self, uuid: &Uuid) -> Option<i64> {
		if let Some(panel) = &self.inner {
			panel.validate_user(uuid).await
		} else {
			None
		}
	}

	/// Get all user IDs (for traffic stats initialization)
	/// Returns empty vec if panel is disabled
	pub async fn get_all_user_ids(&self) -> Vec<i64> {
		if let Some(panel) = &self.inner {
			panel.get_all_user_ids().await
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

	fn make_user(id: i64, uuid: &str) -> User {
		User {
			id,
			uuid: uuid.to_string(),
		}
	}

	fn make_uuid_map(entries: &[(Uuid, i64)]) -> UserMap {
		entries.iter().cloned().collect()
	}

	// ── compute_kicks tests ──────────────────────────────────────────────

	#[test]
	fn test_compute_kicks_no_change() {
		let uuid1 = Uuid::new_v4();
		let uuid2 = Uuid::new_v4();
		let old_map = make_uuid_map(&[(uuid1, 1), (uuid2, 2)]);
		let new_users = vec![
			make_user(1, &uuid1.to_string()),
			make_user(2, &uuid2.to_string()),
		];

		let kicks = compute_kicks(&old_map, &new_users);
		assert!(kicks.is_empty(), "No users changed, no kicks expected");
	}

	#[test]
	fn test_compute_kicks_user_removed() {
		let uuid1 = Uuid::new_v4();
		let uuid2 = Uuid::new_v4();
		let old_map = make_uuid_map(&[(uuid1, 1), (uuid2, 2)]);
		// User 2 removed from new list
		let new_users = vec![make_user(1, &uuid1.to_string())];

		let kicks = compute_kicks(&old_map, &new_users);
		assert_eq!(kicks.len(), 1);
		assert_eq!(kicks[0], uuid2);
	}

	#[test]
	fn test_compute_kicks_all_users_removed() {
		let uuid1 = Uuid::new_v4();
		let uuid2 = Uuid::new_v4();
		let old_map = make_uuid_map(&[(uuid1, 1), (uuid2, 2)]);
		let new_users = vec![];

		let kicks = compute_kicks(&old_map, &new_users);
		assert_eq!(kicks.len(), 2);
		assert!(kicks.contains(&uuid1));
		assert!(kicks.contains(&uuid2));
	}

	#[test]
	fn test_compute_kicks_uuid_changed() {
		let old_uuid = Uuid::new_v4();
		let new_uuid = Uuid::new_v4();
		let old_map = make_uuid_map(&[(old_uuid, 1)]);
		// Same user_id but different UUID
		let new_users = vec![make_user(1, &new_uuid.to_string())];

		let kicks = compute_kicks(&old_map, &new_users);
		assert_eq!(kicks.len(), 1);
		assert_eq!(kicks[0], old_uuid, "Old UUID should be kicked");
	}

	#[test]
	fn test_compute_kicks_new_user_added() {
		let uuid1 = Uuid::new_v4();
		let uuid_new = Uuid::new_v4();
		let old_map = make_uuid_map(&[(uuid1, 1)]);
		// Existing user stays, new user added
		let new_users = vec![
			make_user(1, &uuid1.to_string()),
			make_user(2, &uuid_new.to_string()),
		];

		let kicks = compute_kicks(&old_map, &new_users);
		assert!(kicks.is_empty(), "New user should not cause any kicks");
	}

	#[test]
	fn test_compute_kicks_empty_old_map() {
		let old_map = make_uuid_map(&[]);
		let new_users = vec![make_user(1, &Uuid::new_v4().to_string())];

		let kicks = compute_kicks(&old_map, &new_users);
		assert!(kicks.is_empty(), "Empty old map should produce no kicks");
	}

	#[test]
	fn test_compute_kicks_mixed_changes() {
		let uuid1 = Uuid::new_v4();
		let uuid2 = Uuid::new_v4();
		let uuid3 = Uuid::new_v4();
		let new_uuid2 = Uuid::new_v4();
		let old_map = make_uuid_map(&[(uuid1, 1), (uuid2, 2), (uuid3, 3)]);
		let new_users = vec![
			make_user(1, &uuid1.to_string()),        // unchanged
			make_user(2, &new_uuid2.to_string()),     // UUID changed
			// user 3 removed
			make_user(4, &Uuid::new_v4().to_string()), // new user
		];

		let kicks = compute_kicks(&old_map, &new_users);
		assert_eq!(kicks.len(), 2);
		assert!(kicks.contains(&uuid2), "Changed UUID should be kicked");
		assert!(kicks.contains(&uuid3), "Removed user should be kicked");
		assert!(!kicks.contains(&uuid1), "Unchanged user should not be kicked");
	}

	#[test]
	fn test_compute_kicks_invalid_new_uuid_no_kick() {
		let uuid1 = Uuid::new_v4();
		let old_map = make_uuid_map(&[(uuid1, 1)]);
		// New user has invalid UUID format - the parse fails, so no kick
		let new_users = vec![make_user(1, "not-a-valid-uuid")];

		let kicks = compute_kicks(&old_map, &new_users);
		assert!(kicks.is_empty(), "Invalid new UUID should not trigger a kick");
	}

	// ── rebuild_uuid_map tests ───────────────────────────────────────────

	#[tokio::test]
	async fn test_rebuild_uuid_map_basic() {
		let users_lock = RwLock::new(HashMap::new());
		let uuid1 = Uuid::new_v4();
		let uuid2 = Uuid::new_v4();

		let users = vec![
			make_user(1, &uuid1.to_string()),
			make_user(2, &uuid2.to_string()),
		];

		rebuild_uuid_map(&users_lock, &users).await;

		let map = users_lock.read().await;
		assert_eq!(map.len(), 2);
		assert_eq!(map.get(&uuid1), Some(&1));
		assert_eq!(map.get(&uuid2), Some(&2));
	}

	#[tokio::test]
	async fn test_rebuild_uuid_map_replaces_old_entries() {
		let old_uuid = Uuid::new_v4();
		let new_uuid = Uuid::new_v4();
		let users_lock = RwLock::new(HashMap::from([(old_uuid, 99)]));

		let users = vec![make_user(1, &new_uuid.to_string())];

		rebuild_uuid_map(&users_lock, &users).await;

		let map = users_lock.read().await;
		assert_eq!(map.len(), 1);
		assert!(map.get(&old_uuid).is_none(), "Old UUID should be gone");
		assert_eq!(map.get(&new_uuid), Some(&1));
	}

	#[tokio::test]
	async fn test_rebuild_uuid_map_skips_invalid_uuids() {
		let users_lock = RwLock::new(HashMap::new());
		let valid_uuid = Uuid::new_v4();

		let users = vec![
			make_user(1, &valid_uuid.to_string()),
			make_user(2, "invalid-uuid"),
		];

		rebuild_uuid_map(&users_lock, &users).await;

		let map = users_lock.read().await;
		assert_eq!(map.len(), 1);
		assert_eq!(map.get(&valid_uuid), Some(&1));
	}

	#[tokio::test]
	async fn test_rebuild_uuid_map_empty_list_clears_map() {
		let uuid = Uuid::new_v4();
		let users_lock = RwLock::new(HashMap::from([(uuid, 1)]));

		rebuild_uuid_map(&users_lock, &[]).await;

		let map = users_lock.read().await;
		assert!(map.is_empty());
	}

	// ── OptionalPanel tests ──────────────────────────────────────────────

	#[test]
	fn test_optional_panel_disabled() {
		let panel = OptionalPanel::disabled();
		assert!(!panel.is_enabled());
		assert!(panel.panel().is_none());
		assert!(panel.stats_collector().is_none());
	}

	#[tokio::test]
	async fn test_optional_panel_disabled_validate_user() {
		let panel = OptionalPanel::disabled();
		let uuid = Uuid::new_v4();
		assert_eq!(panel.validate_user(&uuid).await, None);
	}

	#[tokio::test]
	async fn test_optional_panel_disabled_get_all_user_ids() {
		let panel = OptionalPanel::disabled();
		assert!(panel.get_all_user_ids().await.is_empty());
	}
}
