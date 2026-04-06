use std::{collections::HashMap, net::ToSocketAddrs, path::PathBuf, sync::Arc, time::Duration};

use connect_rust_h3::H3TransportBuilder;
use connectrpc::client::{ClientConfig, ServiceTransport};
use serde::{Deserialize, Serialize};
use server_r_agent_proto::pkg::{
	AgentClient, ConfigRequest, HeartbeatRequest, NodeType as GrpcNodeType, RegisterRequest as GrpcRegisterRequest,
	SubmitRequest, UnregisterRequest, UsersRequest, VerifyRequest,
};
use server_r_client::models::{NodeType, TuicConfig, parse_raw_config_response, unmarshal_users};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{AppContext, utils::CongestionController};

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
	/// Congestion control algorithm from API config
	congestion_control: Option<String>,
	/// Server name (SNI) from API config
	server_name:        Option<String>,
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
	/// Panel server host (e.g., "127.0.0.1")
	pub server_host:              String,
	/// Panel server port (e.g., 50051)
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

type PanelClient = AgentClient<ServiceTransport<connect_rust_h3::H3Transport>>;

/// Panel service implementation using Connect RPC over QUIC
pub struct Panel {
	client:      RwLock<Option<PanelClient>>,
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

	/// Connect to the panel via QUIC/H3
	async fn connect(&self) -> eyre::Result<PanelClient> {
		let host_port = format!("{}:{}", self.config.server_host, self.config.server_port);
		info!(
			"Connecting to panel at {} (sni={}, ca={:?})",
			host_port, self.config.server_name, self.config.ca_cert_path
		);

		let addr = host_port
			.to_socket_addrs()
			.map_err(|e| eyre::eyre!("Failed to resolve {}: {}", host_port, e))?
			.next()
			.ok_or_else(|| eyre::eyre!("Failed to resolve {}", host_port))?;

		let mut builder = H3TransportBuilder::new()
			.server_name(&self.config.server_name)
			.keep_alive(Duration::from_secs(15));
		if let Some(ref ca) = self.config.ca_cert_path {
			builder = builder.ca_cert_path(ca);
		}

		let transport = builder
			.build(addr)
			.await
			.map_err(|e| eyre::eyre!("Failed to build H3 transport to {}: {}", host_port, e))?;

		let base_url = format!("https://{}:{}", self.config.server_name, self.config.server_port);
		let config = ClientConfig::new(
			base_url
				.parse()
				.map_err(|e| eyre::eyre!("Invalid base URL {}: {}", base_url, e))?,
		);
		let client = AgentClient::new(ServiceTransport::new(transport), config);

		info!("Connected to panel via QUIC/H3");
		Ok(client)
	}

	/// Get or create panel client
	async fn get_client(&self) -> eyre::Result<PanelClient> {
		let client_guard = self.client.read().await;
		if let Some(client) = client_guard.clone() {
			return Ok(client);
		}
		drop(client_guard);

		let client = self.connect().await?;
		*self.client.write().await = Some(client.clone());
		Ok(client)
	}

	/// Reset the cached panel client to force reconnection on next request
	async fn reset_client(&self) {
		*self.client.write().await = None;
		warn!("Panel client reset, will reconnect on next request");
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

	/// Fetch config from panel server
	async fn fetch_config(&self) -> eyre::Result<TuicConfig> {
		let client = self.get_client().await?;

		let response = client
			.config(ConfigRequest {
				node_id: self.config.node_id as i32,
				node_type: GrpcNodeType::TUIC.into(),
				..Default::default()
			})
			.await
			.map_err(|e| eyre::eyre!("Connect RPC config request failed: {}", e))?;

		let resp = response.into_view();

		if !resp.result {
			return Err(eyre::eyre!("Server returned failure for config request"));
		}

		let raw_data: &[u8] = resp.raw_data;
		let raw_data_str = String::from_utf8_lossy(raw_data);
		debug!("Raw config data from server: {}", raw_data_str);

		let node_config = parse_raw_config_response(NodeType::Tuic, raw_data)
			.map_err(|e| eyre::eyre!("Failed to parse config: {} - raw_data: {}", e, raw_data_str))?;

		let tuic_config = node_config
			.as_tuic()
			.map_err(|e| eyre::eyre!("Failed to get TuicConfig: {}", e))?
			.clone();

		Ok(tuic_config)
	}

	/// Register node with panel server
	async fn register_node(&self, hostname: String, port: u16) -> eyre::Result<String> {
		let client = self.get_client().await?;

		let response = client
			.register(GrpcRegisterRequest {
				node_id: self.config.node_id as i32,
				node_type: GrpcNodeType::TUIC.into(),
				host_name: hostname,
				port: port.to_string(),
				ip: String::new(),
				..Default::default()
			})
			.await
			.map_err(|e| eyre::eyre!("Connect RPC register request failed: {}", e))?;

		Ok(response.into_view().register_id.to_string())
	}

	/// Verify register_id with panel server
	async fn verify_register_id(&self, register_id: &str) -> eyre::Result<bool> {
		let client = self.get_client().await?;

		let response = client
			.verify(VerifyRequest {
				node_type: GrpcNodeType::TUIC.into(),
				register_id: register_id.to_string(),
				..Default::default()
			})
			.await
			.map_err(|e| eyre::eyre!("Connect RPC verify request failed: {}", e))?;

		Ok(response.into_view().result)
	}

	/// Fetch users from panel server and update local storage
	/// Returns the total number of users after update
	/// If ctx is provided, will kick removed users' connections
	async fn fetch_users(&self, ctx: Option<&AppContext>) -> eyre::Result<usize> {
		let client = self.get_client().await?;

		let response = client
			.users(UsersRequest {
				node_type: GrpcNodeType::TUIC.into(),
				node_id: self.config.node_id as i32,
				..Default::default()
			})
			.await
			.map_err(|e| eyre::eyre!("Connect RPC users request failed: {}", e))?;

		let resp = response.into_view();
		let raw_data: &[u8] = resp.raw_data;
		let raw_data_str = String::from_utf8_lossy(raw_data);
		debug!("Raw users data from server: {}", raw_data_str);

		let parsed_users = unmarshal_users(raw_data)
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

		// Release the lock before kicking users to avoid potential deadlocks
		drop(user_map);

		// Kick removed users' connections if ctx is provided
		if !removed.is_empty() {
			if let Some(ctx) = ctx {
				ctx.kick_users(&removed).await;
			}
		}

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

	/// Send heartbeat to panel server
	async fn send_heartbeat(&self) -> eyre::Result<()> {
		let register_id = self.register_id.read().await.clone();
		let register_id = register_id.ok_or_else(|| eyre::eyre!("No register_id available"))?;

		let client = self.get_client().await?;

		let response = client
			.heartbeat(HeartbeatRequest {
				node_type: GrpcNodeType::TUIC.into(),
				register_id,
				..Default::default()
			})
			.await
			.map_err(|e| eyre::eyre!("Connect RPC heartbeat request failed: {}", e))?;

		if response.into_view().result {
			info!("Heartbeat sent successfully");
			Ok(())
		} else {
			Err(eyre::eyre!("Heartbeat failed: server returned false"))
		}
	}

	/// Submit traffic statistics to panel server
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

		let client = self.get_client().await?;

		let response = client
			.submit(SubmitRequest {
				node_type: GrpcNodeType::TUIC.into(),
				register_id,
				raw_data,
				raw_stats,
				..Default::default()
			})
			.await
			.map_err(|e| eyre::eyre!("Connect RPC submit request failed: {}", e))?;

		if response.into_view().result {
			crate::stats::reset_all_traffic(ctx).await;
			info!("Traffic submitted successfully ({} users)", count);
			Ok(())
		} else {
			error!("Failed to submit traffic: server returned false, data retained for next attempt");
			Err(eyre::eyre!("Failed to submit traffic: server returned false"))
		}
	}

	/// Unregister node from panel server
	async fn unregister_node(&self, register_id: &str) -> eyre::Result<()> {
		let client = self.get_client().await?;

		let response = client
			.unregister(UnregisterRequest {
				node_type: GrpcNodeType::TUIC.into(),
				register_id: register_id.to_string(),
				..Default::default()
			})
			.await
			.map_err(|e| eyre::eyre!("Connect RPC unregister request failed: {}", e))?;

		if response.into_view().result {
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
		let mut congestion_control = CongestionController::default();
		let mut node_id: i64 = 0;
		let mut server_name: Option<String> = None;

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
							server_port = port;
							zero_rtt_handshake = zero_rtt;
							node_id = id;
							if let Some(cc_str) = &state.congestion_control {
								match cc_str.parse::<CongestionController>() {
									Ok(cc) => congestion_control = cc,
									Err(_) => warn!(
										"Unknown cached congestion control '{}', using default: {:?}",
										cc_str, congestion_control
									),
								}
							}
							server_name = state.server_name.clone();
							info!(
								"Using cached config - server_port: {}, zero_rtt_handshake: {}, congestion_control: {:?}, id: \
								 {}",
								port, zero_rtt, congestion_control, id
							);
							need_fetch_config = false;
						}
					}
					Ok(false) => {
						warn!("Saved register_id is invalid, will re-register");
						self.delete_state();
					}
					Err(e) => {
						// Network error - don't delete state, exit and retry on next startup
						return Err(eyre::eyre!("Failed to verify register_id: {}", e));
					}
				}
			}
		}

		// Fetch config from panel server if needed
		if need_fetch_config {
			let tuic_config = self.fetch_config().await.map_err(|e| {
				error!("Failed to fetch config from server: {}", e);
				eyre::eyre!("Failed to fetch config from server, cannot continue: {}", e)
			})?;

			info!("Successfully fetched node config: {:?}", tuic_config);

			server_port = tuic_config.server_port;
			zero_rtt_handshake = tuic_config.zero_rtt_handshake;
			node_id = tuic_config.id;
			server_name = tuic_config.server_name.clone();
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
				server_port, zero_rtt_handshake, congestion_control, node_id, server_name
			);
		}

		// Update config with values from panel API or cache
		cfg.server_port = server_port;
		cfg.zero_rtt_handshake = zero_rtt_handshake;
		cfg.congestion_control = congestion_control;
		cfg.server_name = server_name.clone();

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
				congestion_control: Some(format!("{:?}", congestion_control).to_lowercase()),
				server_name:        server_name.clone(),
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
				congestion_control: Some(format!("{:?}", congestion_control).to_lowercase()),
				server_name: server_name.clone(),
			};
			self.save_state(&state)?;
		}

		// Fetch initial user data (no ctx needed since no connections exist yet)
		self.fetch_users(None).await?;

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
					// Pass ctx to kick removed users' connections
					match tokio::time::timeout(task_timeout, self.fetch_users(Some(&ctx))).await {
						Ok(Ok(_)) => {}
						Ok(Err(e)) => {
							error!("Periodic user fetch failed: {}", e);
						}
						Err(_) => {
							error!("Periodic user fetch timed out after {}s, resetting panel client", task_timeout.as_secs());
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
							error!("Heartbeat timed out after {}s, resetting panel client", task_timeout.as_secs());
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
							error!("Traffic submission timed out after {}s, resetting panel client", task_timeout.as_secs());
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
