use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use server_r_client::{
	ApiClient, ApiError, Config as ApiConfig, NodeConfigEnum, NodeType, RegisterRequest,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, RwLock};
use tracing::{error, info, warn};
use uuid::Uuid;

/// State file name
const STATE_FILE: &str = "state.json";

/// Persistent state for the panel
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PanelState {
	/// Registration ID obtained from API
	register_id: Option<String>,
}

fn get_hostname() -> String {
	hostname::get()
		.map(|h| h.to_string_lossy().to_string())
		.unwrap_or_else(|_| "unknown".to_string())
}

/// Trait defining the lifecycle of a panel service
#[async_trait::async_trait]
pub trait PanelService: Send + Sync {
	/// Initialize the service (called before server starts)
	async fn init(&self) -> eyre::Result<()>;

	/// Run the service (called while server is running)
	/// This method should be spawned as a background task
	async fn run(&self) -> eyre::Result<()>;

	/// Close the service (called when server is shutting down)
	async fn close(&self) -> eyre::Result<()>;
}

/// Configuration for the panel service
#[derive(Debug, Clone)]
pub struct PanelConfig {
	/// API host URL (e.g., "https://api.example.com")
	pub api_host: String,
	/// Authentication token
	pub token: String,
	/// Node ID for this server
	pub node_id: u32,
	/// Request timeout in seconds
	pub timeout: u64,
	/// Interval for fetching users from API (in seconds)
	pub fetch_users_interval: u64,
	/// Interval for reporting traffic stats to API (in seconds)
	pub report_traffics_interval: u64,
	/// Interval for sending heartbeat to API (in seconds)
	pub heartbeat_interval: u64,
	/// Data directory for persisting state and other data
	pub data_dir: PathBuf,
}

/// User data stored in Panel
/// Maps UUID -> user_id (i64)
type UserMap = HashMap<Uuid, i64>;

/// Panel service implementation using server-r-client
pub struct Panel {
	client: ApiClient,
	config: PanelConfig,
	running: RwLock<bool>,
	/// Notify to signal shutdown to background tasks
	shutdown: Notify,
	/// Registration ID obtained from API during init
	register_id: RwLock<Option<String>>,
	/// User data: UUID -> user_id mapping
	users: RwLock<UserMap>,
}

impl Panel {
	/// Create a new Panel instance
	pub fn new(config: PanelConfig) -> eyre::Result<Self> {
		let api_config = ApiConfig::new(&config.api_host, &config.token)
			.with_timeout(Duration::from_secs(config.timeout));

		let client = ApiClient::new(api_config)
			.map_err(|e| eyre::eyre!("Failed to create API client: {}", e))?;

		Ok(Self {
			client,
			config,
			running: RwLock::new(false),
			shutdown: Notify::new(),
			register_id: RwLock::new(None),
			users: RwLock::new(HashMap::new()),
		})
	}

	/// Get a reference to the API client
	pub fn client(&self) -> &ApiClient {
		&self.client
	}

	/// Get the node ID
	pub fn node_id(&self) -> u32 {
		self.config.node_id
	}

	/// Validate a user by UUID, returns the user_id if valid
	pub async fn validate_user(&self, uuid: &Uuid) -> Option<i64> {
		self.users.read().await.get(uuid).copied()
	}

	/// Get all user IDs (for traffic stats initialization)
	pub async fn get_all_user_ids(&self) -> Vec<i64> {
		self.users.read().await.values().copied().collect()
	}

	/// Get the state file path
	fn state_file_path(&self) -> PathBuf {
		self.config.data_dir.join(STATE_FILE)
	}

	/// Load state from file
	fn load_state(&self) -> Option<PanelState> {
		let path = self.state_file_path();
		if !path.exists() {
			return None;
		}

		match std::fs::read_to_string(&path) {
			Ok(content) => match serde_json::from_str(&content) {
				Ok(state) => {
					info!("Loaded state from {:?}", path);
					Some(state)
				}
				Err(e) => {
					warn!("Failed to parse state file: {}", e);
					None
				}
			},
			Err(e) => {
				warn!("Failed to read state file: {}", e);
				None
			}
		}
	}

	/// Save state to file
	fn save_state(&self, state: &PanelState) -> eyre::Result<()> {
		let path = self.state_file_path();
		let content = serde_json::to_string_pretty(state)
			.map_err(|e| eyre::eyre!("Failed to serialize state: {}", e))?;

		std::fs::write(&path, content)
			.map_err(|e| eyre::eyre!("Failed to write state file {:?}: {}", path, e))?;

		info!("Saved state to {:?}", path);
		Ok(())
	}

	/// Delete state file
	fn delete_state(&self) {
		let path = self.state_file_path();
		if path.exists() {
			if let Err(e) = std::fs::remove_file(&path) {
				warn!("Failed to delete state file {:?}: {}", path, e);
			} else {
				info!("Deleted state file {:?}", path);
			}
		}
	}

	/// Fetch users from API and update local storage
	/// Returns the total number of users after update
	async fn fetch_users(&self) -> eyre::Result<usize> {
		let register_id = self.register_id.read().await.clone();
		let register_id = register_id.ok_or_else(|| eyre::eyre!("No register_id available"))?;

		match self
			.client
			.users(NodeType::Tuic, &register_id)
			.await
		{
			Ok(users) => {
				// Build new user map from API response
				let mut new_user_map: UserMap = HashMap::new();
				for user in &users {
					if let Ok(uuid) = Uuid::parse_str(&user.uuid) {
						new_user_map.insert(uuid, user.id);
					} else {
						warn!("Invalid UUID format for user {}: {}", user.id, user.uuid);
					}
				}

				// Compare with existing users and update
				let mut user_map = self.users.write().await;

				// Find users to remove (exist in current but not in new)
				let removed: Vec<Uuid> = user_map
					.keys()
					.filter(|uuid| !new_user_map.contains_key(*uuid))
					.copied()
					.collect();

				// Find users to add (exist in new but not in current)
				let added: Vec<Uuid> = new_user_map
					.keys()
					.filter(|uuid| !user_map.contains_key(*uuid))
					.copied()
					.collect();

				// Apply changes
				for uuid in &removed {
					user_map.remove(uuid);
				}
				for uuid in &added {
					if let Some(user_id) = new_user_map.get(uuid) {
						user_map.insert(*uuid, *user_id);
					}
				}

				let count = user_map.len();
				if !removed.is_empty() || !added.is_empty() {
					info!(
						"Users updated: {} added, {} removed, {} total",
						added.len(),
						removed.len(),
						count
					);
				} else {
					info!("Fetched {} users from API (no changes)", count);
				}
				Ok(count)
			}
			Err(ApiError::NotModified { .. }) => {
				info!("Users not modified (ETag match)");
				Ok(self.users.read().await.len())
			}
			Err(e) => {
				error!("Failed to fetch users: {}", e);
				Err(eyre::eyre!("Failed to fetch users: {}", e))
			}
		}
	}

	/// Send heartbeat to API server
	async fn send_heartbeat(&self) -> eyre::Result<()> {
		let register_id = self.register_id.read().await.clone();
		let register_id = register_id.ok_or_else(|| eyre::eyre!("No register_id available"))?;

		match self.client.heartbeat(NodeType::Tuic, &register_id).await {
			Ok(()) => {
				info!("Heartbeat sent successfully");
				Ok(())
			}
			Err(e) => {
				error!("Failed to send heartbeat: {}", e);
				Err(eyre::eyre!("Failed to send heartbeat: {}", e))
			}
		}
	}
}

#[async_trait::async_trait]
impl PanelService for Panel {
	async fn init(&self) -> eyre::Result<()> {
		info!("Panel service initializing...");

		// Ensure data directory exists
		if !self.config.data_dir.exists() {
			info!("Creating data directory: {:?}", self.config.data_dir);
			std::fs::create_dir_all(&self.config.data_dir).map_err(|e| {
				error!("Failed to create data directory: {}", e);
				eyre::eyre!("Failed to create data directory {:?}: {}", self.config.data_dir, e)
			})?;
		}

		// Try to load existing state and verify register_id
		let mut need_register = true;
		if let Some(state) = self.load_state() {
			if let Some(saved_register_id) = state.register_id {
				info!("Found saved register_id, verifying...");
				match self.client.verify(NodeType::Tuic, &saved_register_id).await {
					Ok(true) => {
						info!("Saved register_id is valid, skipping registration");
						*self.register_id.write().await = Some(saved_register_id);
						need_register = false;
					}
					Ok(false) => {
						warn!("Saved register_id is invalid, will re-register");
						self.delete_state();
					}
					Err(e) => {
						warn!("Failed to verify register_id: {}, will re-register", e);
						self.delete_state();
					}
				}
			}
		}

		if need_register {
			// Fetch config from API - this is critical, exit if it fails
			let node_config = self
				.client
				.config(NodeType::Tuic, self.config.node_id as i64)
				.await
				.map_err(|e| {
					error!("Failed to fetch config from API: {}", e);
					eyre::eyre!(
						"Failed to fetch config from API, cannot continue: {}",
						e
					)
				})?;

			info!("Successfully fetched node config: {:?}", node_config);

			// Convert to TuicConfig
			let tuic_config = match node_config {
				NodeConfigEnum::Tuic(config) => config,
				_ => {
					error!("Expected Tuic config but got different type");
					return Err(eyre::eyre!(
						"Expected Tuic config but got different type, cannot continue"
					));
				}
			};

			info!(
				"Tuic config - server_port: {}, id: {}",
				tuic_config.server_port, tuic_config.id
			);

			// Get hostname and register node
			let hostname = get_hostname();
			let register_request = RegisterRequest::new(hostname.clone(), tuic_config.server_port);

			info!(
				"Registering node with hostname: {}, port: {}",
				hostname, tuic_config.server_port
			);

			let register_id = self
				.client
				.register(
					NodeType::Tuic,
					self.config.node_id as i64,
					register_request,
				)
				.await
				.map_err(|e| {
					error!("Failed to register node: {}", e);
					eyre::eyre!("Failed to register node, cannot continue: {}", e)
				})?;

			info!("Node registered successfully, register_id: {}", register_id);

			// Save register_id for later use
			{
				*self.register_id.write().await = Some(register_id.clone());
			}

			// Persist state to file
			let state = PanelState {
				register_id: Some(register_id),
			};
			self.save_state(&state)?;
		}

		// Fetch initial user data
		self.fetch_users().await?;

		// Send initial heartbeat
		self.send_heartbeat().await?;

		info!("Panel service initialized");
		Ok(())
	}

	async fn run(&self) -> eyre::Result<()> {
		{
			*self.running.write().await = true;
		}

		info!("Panel service running...");

		let fetch_interval = Duration::from_secs(self.config.fetch_users_interval);
		let heartbeat_interval = Duration::from_secs(self.config.heartbeat_interval);

		info!(
			"Starting periodic tasks (user fetch: {}s, heartbeat: {}s)",
			self.config.fetch_users_interval, self.config.heartbeat_interval
		);

		let mut fetch_timer = tokio::time::interval(fetch_interval);
		let mut heartbeat_timer = tokio::time::interval(heartbeat_interval);

		// Skip the first immediate tick
		fetch_timer.tick().await;
		heartbeat_timer.tick().await;

		// Periodic tasks loop
		loop {
			tokio::select! {
				_ = self.shutdown.notified() => {
					info!("Received shutdown signal, stopping periodic tasks");
					break;
				}
				_ = fetch_timer.tick() => {
					// Fetch users periodically
					if let Err(e) = self.fetch_users().await {
						error!("Periodic user fetch failed: {}", e);
					}
				}
				_ = heartbeat_timer.tick() => {
					// Send heartbeat periodically
					if let Err(e) = self.send_heartbeat().await {
						error!("Heartbeat failed: {}", e);
					}
				}
			}
		}

		info!("Panel service stopped");
		Ok(())
	}

	async fn close(&self) -> eyre::Result<()> {
		info!("Panel service closing...");

		// Signal shutdown to stop periodic tasks
		self.shutdown.notify_waiters();

		{
			*self.running.write().await = false;
		}

		// Unregister node if we have a register_id
		let register_id = self.register_id.read().await.clone();
		if let Some(rid) = register_id {
			info!("Unregistering node with register_id: {}", rid);
			match self.client.unregister(NodeType::Tuic, &rid).await {
				Ok(()) => {
					info!("Node unregistered successfully");
					// Clear state file after successful unregister
					self.delete_state();
					// Clear register_id in memory
					*self.register_id.write().await = None;
				}
				Err(e) => {
					warn!("Failed to unregister node: {}", e);
				}
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
}

#[async_trait::async_trait]
impl PanelService for OptionalPanel {
	async fn init(&self) -> eyre::Result<()> {
		if let Some(panel) = &self.inner {
			panel.init().await
		} else {
			warn!("Panel service is disabled, skipping init");
			Ok(())
		}
	}

	async fn run(&self) -> eyre::Result<()> {
		if let Some(panel) = &self.inner {
			panel.run().await
		} else {
			// Panel is disabled, just return immediately
			Ok(())
		}
	}

	async fn close(&self) -> eyre::Result<()> {
		if let Some(panel) = &self.inner {
			panel.close().await
		} else {
			warn!("Panel service is disabled, skipping close");
			Ok(())
		}
	}
}
