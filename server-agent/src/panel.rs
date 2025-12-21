use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use server_r_agent_proto::pkg::{
	ConfigRequest, ConfigResponse, HeartbeatRequest, NodeType as GrpcNodeType, RegisterRequest as GrpcRegisterRequest,
	SubmitRequest, UnregisterRequest, UsersRequest, VerifyRequest, agent_client::AgentClient,
};
use server_r_client::models::{NodeType, TuicConfig, parse_raw_config_response, unmarshal_users};
use tokio::sync::RwLock;
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::AppContext;

/// State file name
const STATE_FILE: &str = "state.json";

/// Persistent state for the panel
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PanelState {
	/// Registration ID obtained from API
	register_id:        Option<String>,
	/// Node ID from API config
	node_id:            Option<i64>,
	/// Server port from API config
	server_port:        Option<u16>,
	/// Zero RTT handshake setting from API config
	zero_rtt_handshake: Option<bool>,
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
	/// Updates the config with values fetched from panel API (e.g.,
	/// server_port)
	async fn init(&self, cfg: &mut crate::Config) -> eyre::Result<()>;

	/// Run the service (called while server is running)
	/// This method should be spawned as a background task
	/// The ctx parameter provides access to traffic statistics
	async fn run(&self, ctx: Arc<AppContext>) -> eyre::Result<()>;

	/// Close the service (called when server is shutting down)
	async fn close(&self) -> eyre::Result<()>;
}

/// Configuration for the panel service
#[derive(Debug, Clone)]
pub struct PanelConfig {
	/// gRPC server host (e.g., "127.0.0.1")
	pub server_host:              String,
	/// gRPC server port (e.g., 50051)
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
}

/// User information from server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
	pub id:   i64,
	pub uuid: String,
}

/// User traffic data for submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserTraffic {
	pub user_id: i64,
	/// Upload bytes
	pub u:       u64,
	/// Download bytes
	pub d:       u64,
	/// Count/connections
	#[serde(default)]
	pub n:       u64,
}

impl UserTraffic {
	/// Create a new UserTraffic instance with connection count
	pub fn with_count(user_id: i64, upload: u64, download: u64, count: u64) -> Self {
		Self {
			user_id,
			u: upload,
			d: download,
			n: count,
		}
	}
}

/// Aggregated traffic statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrafficStats {
	/// Total count
	pub count:         i64,
	/// Total requests
	pub requests:      i64,
	/// User IDs
	pub user_ids:      Vec<i64>,
	/// Per-user request counts
	#[serde(default)]
	pub user_requests: std::collections::HashMap<i64, i64>,
}

impl TrafficStats {
	/// Create a new empty TrafficStats instance
	pub fn new() -> Self {
		Self {
			count:         0,
			requests:      0,
			user_ids:      Vec::new(),
			user_requests: std::collections::HashMap::new(),
		}
	}

	/// Add a user's request count
	pub fn add_user(&mut self, user_id: i64, requests: i64) {
		self.user_ids.push(user_id);
		self.user_requests.insert(user_id, requests);
		self.requests += requests;
		self.count += 1;
	}
}

/// User data stored in Panel
/// Maps UUID -> user_id (i64)
type UserMap = HashMap<Uuid, i64>;

/// Panel service implementation using gRPC client
pub struct Panel {
	client:      RwLock<Option<AgentClient<Channel>>>,
	config:      PanelConfig,
	running:     RwLock<bool>,
	/// Registration ID obtained from API during init
	register_id: RwLock<Option<String>>,
	/// User data: UUID -> user_id mapping
	users:       RwLock<UserMap>,
}

impl Panel {
	/// Create a new Panel instance
	pub fn new(config: PanelConfig) -> eyre::Result<Self> {
		Ok(Self {
			client: RwLock::new(None),
			config,
			running: RwLock::new(false),
			register_id: RwLock::new(None),
			users: RwLock::new(HashMap::new()),
		})
	}

	/// Connect to the gRPC server
	async fn connect(&self) -> eyre::Result<AgentClient<Channel>> {
		let endpoint = format!("http://{}:{}", self.config.server_host, self.config.server_port);
		let timeout = Duration::from_secs(self.config.request_timeout);
		info!(
			"Connecting to gRPC server at {} (timeout: {}s)",
			endpoint, self.config.request_timeout
		);

		let channel = Channel::from_shared(endpoint.clone())
			.map_err(|e| eyre::eyre!("Invalid endpoint: {}", e))?
			.connect_timeout(timeout)
			.timeout(timeout)
			.connect()
			.await
			.map_err(|e| eyre::eyre!("Failed to connect to gRPC server {}: {}", endpoint, e))?;

		let client = AgentClient::new(channel);
		info!("Connected to gRPC server");
		Ok(client)
	}

	/// Get or create gRPC client
	async fn get_client(&self) -> eyre::Result<AgentClient<Channel>> {
		let client_guard = self.client.read().await;
		if let Some(client) = client_guard.clone() {
			return Ok(client);
		}
		drop(client_guard);

		let client = self.connect().await?;
		*self.client.write().await = Some(client.clone());
		Ok(client)
	}

	/// Reset the cached gRPC client to force reconnection on next request
	async fn reset_client(&self) {
		*self.client.write().await = None;
		warn!("gRPC client reset, will reconnect on next request");
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
		let content = serde_json::to_string_pretty(state).map_err(|e| eyre::eyre!("Failed to serialize state: {}", e))?;

		std::fs::write(&path, content).map_err(|e| eyre::eyre!("Failed to write state file {:?}: {}", path, e))?;

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

	/// Fetch config from gRPC server
	async fn fetch_config(&self) -> eyre::Result<TuicConfig> {
		let mut client = self.get_client().await?;

		let request = tonic::Request::new(ConfigRequest {
			node_id:   self.config.node_id as i32,
			node_type: GrpcNodeType::Tuic as i32,
		});

		let response = client
			.config(request)
			.await
			.map_err(|e| eyre::eyre!("gRPC config request failed: {}", e))?;

		let config_response: ConfigResponse = response.into_inner();

		if !config_response.result {
			return Err(eyre::eyre!("Server returned failure for config request"));
		}

		let raw_data_str = String::from_utf8_lossy(&config_response.raw_data);
		debug!("Raw config data from server: {}", raw_data_str);

		let node_config = parse_raw_config_response(NodeType::Tuic, &config_response.raw_data)
			.map_err(|e| eyre::eyre!("Failed to parse config: {} - raw_data: {}", e, raw_data_str))?;

		let tuic_config = node_config
			.as_tuic()
			.map_err(|e| eyre::eyre!("Failed to get TuicConfig: {}", e))?
			.clone();

		Ok(tuic_config)
	}

	/// Register node with gRPC server
	async fn register_node(&self, hostname: String, port: u16) -> eyre::Result<String> {
		let mut client = self.get_client().await?;

		let request = tonic::Request::new(GrpcRegisterRequest {
			node_id:   self.config.node_id as i32,
			node_type: GrpcNodeType::Tuic as i32,
			host_name: hostname,
			port:      port.to_string(),
			ip:        String::new(),
		});

		let response = client
			.register(request)
			.await
			.map_err(|e| eyre::eyre!("gRPC register request failed: {}", e))?;

		Ok(response.into_inner().register_id)
	}

	/// Verify register_id with gRPC server
	async fn verify_register_id(&self, register_id: &str) -> eyre::Result<bool> {
		let mut client = self.get_client().await?;

		let request = tonic::Request::new(VerifyRequest {
			node_type:   GrpcNodeType::Tuic as i32,
			register_id: register_id.to_string(),
		});

		let response = client
			.verify(request)
			.await
			.map_err(|e| eyre::eyre!("gRPC verify request failed: {}", e))?;

		Ok(response.into_inner().result)
	}

	/// Fetch users from gRPC server and update local storage
	/// Returns the total number of users after update
	async fn fetch_users(&self) -> eyre::Result<usize> {
		let register_id = self.register_id.read().await.clone();
		let register_id = register_id.ok_or_else(|| eyre::eyre!("No register_id available"))?;

		let mut client = self.get_client().await?;

		let request = tonic::Request::new(UsersRequest {
			node_type:   GrpcNodeType::Tuic as i32,
			register_id: register_id.clone(),
		});

		let response = client
			.users(request)
			.await
			.map_err(|e| eyre::eyre!("gRPC users request failed: {}", e))?;

		let users_response = response.into_inner();
		let raw_data_str = String::from_utf8_lossy(&users_response.raw_data);
		debug!("Raw users data from server: {}", raw_data_str);

		let parsed_users = unmarshal_users(&users_response.raw_data)
			.map_err(|e| eyre::eyre!("Failed to parse users response: {} - raw_data: {}", e, raw_data_str))?;

		let users: Vec<User> = parsed_users
			.into_iter()
			.map(|u| User {
				id:   u.id,
				uuid: u.uuid,
			})
			.collect();

		// Build new user map from response
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
			info!("Fetched {} users from server (no changes)", count);
		}
		Ok(count)
	}

	/// Send heartbeat to gRPC server
	async fn send_heartbeat(&self) -> eyre::Result<()> {
		let register_id = self.register_id.read().await.clone();
		let register_id = register_id.ok_or_else(|| eyre::eyre!("No register_id available"))?;

		let mut client = self.get_client().await?;

		let request = tonic::Request::new(HeartbeatRequest {
			node_type: GrpcNodeType::Tuic as i32,
			register_id,
		});

		let response = client
			.heartbeat(request)
			.await
			.map_err(|e| eyre::eyre!("gRPC heartbeat request failed: {}", e))?;

		if response.into_inner().result {
			info!("Heartbeat sent successfully");
			Ok(())
		} else {
			Err(eyre::eyre!("Heartbeat failed: server returned false"))
		}
	}

	/// Submit traffic statistics to gRPC server
	/// Only resets counters on successful submission to avoid data loss
	async fn submit_traffic(&self, ctx: &AppContext) -> eyre::Result<()> {
		let register_id = self.register_id.read().await.clone();
		let register_id = register_id.ok_or_else(|| eyre::eyre!("No register_id available"))?;

		// Get traffic stats without resetting
		let traffic_data = crate::stats::get_all_traffic(ctx).await;

		// Filter out entries with no traffic or no requests
		let traffic_list: Vec<UserTraffic> = traffic_data
			.into_iter()
			.filter(|(_, tx, rx, conn)| (*tx > 0 || *rx > 0) && *conn > 0)
			.map(|(uid, tx, rx, conn)| UserTraffic::with_count(uid, tx as u64, rx as u64, conn as u64))
			.collect();

		if traffic_list.is_empty() {
			info!("No traffic to submit");
			return Ok(());
		}

		let count = traffic_list.len();

		// Build TrafficStats for raw_stats
		let mut stats = TrafficStats::new();
		for traffic in &traffic_list {
			stats.add_user(traffic.user_id, traffic.n as i64);
		}

		let raw_data = serde_json::to_vec(&traffic_list).map_err(|e| eyre::eyre!("Failed to serialize traffic data: {}", e))?;
		let raw_stats = serde_json::to_vec(&stats).map_err(|e| eyre::eyre!("Failed to serialize traffic stats: {}", e))?;

		let mut client = self.get_client().await?;

		let request = tonic::Request::new(SubmitRequest {
			node_type: GrpcNodeType::Tuic as i32,
			register_id,
			raw_data,
			raw_stats,
		});

		let response = client
			.submit(request)
			.await
			.map_err(|e| eyre::eyre!("gRPC submit request failed: {}", e))?;

		if response.into_inner().result {
			// Only reset counters after successful submission
			crate::stats::reset_all_traffic(ctx).await;
			info!("Traffic submitted successfully ({} users)", count);
			Ok(())
		} else {
			error!("Failed to submit traffic: server returned false, data retained for next attempt");
			Err(eyre::eyre!("Failed to submit traffic: server returned false"))
		}
	}

	/// Unregister node from gRPC server
	async fn unregister_node(&self, register_id: &str) -> eyre::Result<()> {
		let mut client = self.get_client().await?;

		let request = tonic::Request::new(UnregisterRequest {
			node_type:   GrpcNodeType::Tuic as i32,
			register_id: register_id.to_string(),
		});

		let response = client
			.unregister(request)
			.await
			.map_err(|e| eyre::eyre!("gRPC unregister request failed: {}", e))?;

		if response.into_inner().result {
			info!("Node unregistered successfully");
			Ok(())
		} else {
			Err(eyre::eyre!("Unregister failed: server returned false"))
		}
	}
}

#[async_trait::async_trait]
impl PanelService for Panel {
	async fn init(&self, cfg: &mut crate::Config) -> eyre::Result<()> {
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
		let mut need_fetch_config = true;
		let mut server_port: u16 = 0;
		let mut zero_rtt_handshake = false;
		let mut node_id: i64 = 0;

		if let Some(state) = self.load_state() {
			if let Some(saved_register_id) = &state.register_id {
				info!("Found saved register_id, verifying...");
				match self.verify_register_id(saved_register_id).await {
					Ok(true) => {
						info!("Saved register_id is valid, skipping registration");
						*self.register_id.write().await = Some(saved_register_id.clone());
						need_register = false;

						// Use cached config if available
						if let (Some(port), Some(zero_rtt), Some(id)) =
							(state.server_port, state.zero_rtt_handshake, state.node_id)
						{
							info!(
								"Using cached config - server_port: {}, zero_rtt_handshake: {}, id: {}",
								port, zero_rtt, id
							);
							server_port = port;
							zero_rtt_handshake = zero_rtt;
							node_id = id;
							need_fetch_config = false;
						}
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

		// Fetch config from gRPC server if needed
		if need_fetch_config {
			let tuic_config = self.fetch_config().await.map_err(|e| {
				error!("Failed to fetch config from server: {}", e);
				eyre::eyre!("Failed to fetch config from server, cannot continue: {}", e)
			})?;

			info!("Successfully fetched node config: {:?}", tuic_config);

			server_port = tuic_config.server_port;
			zero_rtt_handshake = tuic_config.zero_rtt_handshake;
			node_id = tuic_config.id;
			info!(
				"Tuic config - server_port: {}, zero_rtt_handshake: {}, id: {}",
				server_port, zero_rtt_handshake, node_id
			);
		}

		// Update config with values from panel API or cache
		cfg.server_port = server_port;
		cfg.zero_rtt_handshake = zero_rtt_handshake;

		if need_register {
			// Get hostname and register node
			let hostname = get_hostname();

			info!("Registering node with hostname: {}, port: {}", hostname, server_port);

			let register_id = self.register_node(hostname, server_port).await.map_err(|e| {
				error!("Failed to register node: {}", e);
				eyre::eyre!("Failed to register node, cannot continue: {}", e)
			})?;

			info!("Node registered successfully, register_id: {}", register_id);

			// Save register_id for later use
			*self.register_id.write().await = Some(register_id.clone());

			// Persist state to file with all config info
			let state = PanelState {
				register_id:        Some(register_id),
				node_id:            Some(node_id),
				server_port:        Some(server_port),
				zero_rtt_handshake: Some(zero_rtt_handshake),
			};
			self.save_state(&state)?;
		} else if need_fetch_config {
			// Update state file with new config info (register_id unchanged)
			let register_id = self.register_id.read().await.clone();
			let state = PanelState {
				register_id,
				node_id: Some(node_id),
				server_port: Some(server_port),
				zero_rtt_handshake: Some(zero_rtt_handshake),
			};
			self.save_state(&state)?;
		}

		// Fetch initial user data
		self.fetch_users().await?;

		// Send initial heartbeat
		self.send_heartbeat().await?;

		info!("Panel service initialized, server_port: {}", server_port);
		Ok(())
	}

	async fn run(&self, ctx: Arc<AppContext>) -> eyre::Result<()> {
		{
			*self.running.write().await = true;
		}

		info!("Panel service running...");

		let fetch_interval = Duration::from_secs(self.config.fetch_users_interval);
		let heartbeat_interval = Duration::from_secs(self.config.heartbeat_interval);
		let report_interval = Duration::from_secs(self.config.report_traffics_interval);
		let task_timeout = Duration::from_secs(self.config.request_timeout);

		info!(
			"Starting periodic tasks (user fetch: {}s, heartbeat: {}s, report traffic: {}s, task timeout: {}s)",
			self.config.fetch_users_interval,
			self.config.heartbeat_interval,
			self.config.report_traffics_interval,
			self.config.request_timeout
		);

		let mut fetch_timer = tokio::time::interval(fetch_interval);
		let mut heartbeat_timer = tokio::time::interval(heartbeat_interval);
		let mut report_timer = tokio::time::interval(report_interval);

		// Skip the first immediate tick
		fetch_timer.tick().await;
		heartbeat_timer.tick().await;
		report_timer.tick().await;

		// Subscribe to shutdown signal from AppContext
		let mut shutdown_rx = ctx.shutdown_tx.subscribe();

		// Periodic tasks loop
		loop {
			tokio::select! {
				result = shutdown_rx.recv() => {
					match result {
						Ok(()) | Err(tokio::sync::broadcast::error::RecvError::Closed) => {
							info!("Received shutdown signal, stopping periodic tasks");
							break;
						}
						Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
							warn!("Shutdown receiver lagged by {} messages, continuing", n);
							// Continue the loop, don't break
						}
					}
				}
				_ = fetch_timer.tick() => {
					// Fetch users periodically with timeout protection
					match tokio::time::timeout(task_timeout, self.fetch_users()).await {
						Ok(Ok(_)) => {}
						Ok(Err(e)) => {
							error!("Periodic user fetch failed: {}", e);
						}
						Err(_) => {
							error!("Periodic user fetch timed out after {}s, resetting gRPC client", task_timeout.as_secs());
							self.reset_client().await;
						}
					}
				}
				_ = heartbeat_timer.tick() => {
					// Send heartbeat periodically with timeout protection
					match tokio::time::timeout(task_timeout, self.send_heartbeat()).await {
						Ok(Ok(_)) => {}
						Ok(Err(e)) => {
							error!("Heartbeat failed: {}", e);
						}
						Err(_) => {
							error!("Heartbeat timed out after {}s, resetting gRPC client", task_timeout.as_secs());
							self.reset_client().await;
						}
					}
				}
				_ = report_timer.tick() => {
					// Submit traffic stats periodically with timeout protection
					match tokio::time::timeout(task_timeout, self.submit_traffic(&ctx)).await {
						Ok(Ok(_)) => {}
						Ok(Err(e)) => {
							error!("Traffic submission failed: {}", e);
						}
						Err(_) => {
							error!("Traffic submission timed out after {}s, resetting gRPC client", task_timeout.as_secs());
							self.reset_client().await;
						}
					}
				}
			}
		}

		info!("Panel service stopped");
		Ok(())
	}

	async fn close(&self) -> eyre::Result<()> {
		info!("Panel service closing...");

		{
			*self.running.write().await = false;
		}

		// Unregister node if we have a register_id
		let register_id = self.register_id.read().await.clone();
		if let Some(rid) = register_id {
			info!("Unregistering node with register_id: {}", rid);
			match self.unregister_node(&rid).await {
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
	async fn init(&self, cfg: &mut crate::Config) -> eyre::Result<()> {
		if let Some(panel) = &self.inner {
			panel.init(cfg).await
		} else {
			error!("Panel service is required but not configured");
			Err(eyre::eyre!("Panel service is required to get server_port from API"))
		}
	}

	async fn run(&self, ctx: Arc<AppContext>) -> eyre::Result<()> {
		if let Some(panel) = &self.inner {
			panel.run(ctx).await
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
