// Library interface for server
// This allows the server to be used as a library in integration tests

use std::{collections::HashMap, sync::Arc};

use moka::future::Cache;
use quinn::Connection as QuinnConnection;
use tokio::sync::{RwLock as AsyncRwLock, broadcast};
use tracing::{error, info, warn};
use uuid::Uuid;

pub mod acl;
pub mod config;
pub mod congestion;
pub mod connection;
pub mod error;
pub mod io;
pub mod panel;
pub mod server;
pub mod stats;
pub mod tls;
pub mod utils;

pub use config::{Cli, Config, Control};
pub use panel::{OptionalPanel, Panel};

/// Per-user connection map: connection_id -> QuinnConnection
pub type UserConnections = Arc<AsyncRwLock<HashMap<usize, QuinnConnection>>>;

/// Online clients registry: UUID -> UserConnections
/// Used to track and manage active connections per user
pub type OnlineClients = Cache<Uuid, UserConnections>;

/// Error code for kicked clients
const KICK_ERROR_CODE: quinn::VarInt = quinn::VarInt::from_u32(6002);

pub struct AppContext {
	pub cfg:            Config,
	pub panel_service:  Arc<OptionalPanel>,
	pub shutdown_tx:    broadcast::Sender<()>,
	/// Online clients registry for connection management
	pub online_clients: OnlineClients,
}

impl AppContext {
	/// Kick users by closing all their active connections
	/// This should be called when users are removed from the panel
	pub async fn kick_users(&self, uuids: &[Uuid]) {
		use tracing::debug;

		for uuid in uuids {
			if let Some(user_conns) = self.online_clients.get(uuid).await {
				let conns = user_conns.read().await;
				let kicked_count = conns.len();

				// Close all connections for this user
				for (conn_id, conn) in conns.iter() {
					conn.close(KICK_ERROR_CODE, b"User removed");
					debug!("[{id:#010x}] [{uuid}] kicked connection", id = conn_id,);
				}

				drop(conns); // Release lock before removing from cache

				// Remove the user from online clients cache
				self.online_clients.remove(uuid).await;

				if kicked_count > 0 {
					info!("Kicked {} connection(s) for removed user {}", kicked_count, uuid);
				}
			}
		}
	}
}

/// Run the TUIC server with the given configuration
pub async fn run(mut cfg: Config) -> eyre::Result<()> {
	// Initialize panel service if configured
	let panel_service = if let Some(panel_cfg) = &cfg.panel {
		info!(
			"Panel service enabled, connecting to {}:{}",
			panel_cfg.server_host, panel_cfg.server_port
		);
		let panel = Panel::new(panel_cfg.clone())?;
		OptionalPanel::with_panel(panel)
	} else {
		warn!("Panel service disabled (no panel configuration provided)");
		OptionalPanel::disabled()
	};

	let panel_service = Arc::new(panel_service);

	// Initialize panel service before server starts
	// This updates cfg with values from panel API (e.g., server_port)
	panel_service.init(&mut cfg).await?;

	// Spawn run_inner in a separate task to catch panics
	let panel_for_inner = panel_service.clone();
	let handle = tokio::spawn(async move { run_inner(panel_for_inner, cfg).await });

	// Wait for the task to complete and handle both normal completion and panic
	let result = match handle.await {
		Ok(inner_result) => inner_result,
		Err(join_error) => {
			if join_error.is_panic() {
				error!("Server task panicked: {:?}", join_error);
				Err(eyre::eyre!("Server task panicked"))
			} else if join_error.is_cancelled() {
				error!("Server task was cancelled");
				Err(eyre::eyre!("Server task was cancelled"))
			} else {
				error!("Server task failed: {:?}", join_error);
				Err(eyre::eyre!("Server task failed: {:?}", join_error))
			}
		}
	};

	// Close panel service (unregister node)
	info!("Closing panel service...");
	if let Err(e) = panel_service.close().await {
		error!("Failed to close panel service: {}", e);
	}

	result
}

/// Inner run function that can return early on error
async fn run_inner(panel_service: Arc<OptionalPanel>, cfg: Config) -> eyre::Result<()> {
	// Create shutdown signal channel
	let (shutdown_tx, _) = broadcast::channel::<()>(1);

	// Online clients cache with no TTL (connections are manually managed)
	let online_clients: OnlineClients = Cache::builder().build();

	let ctx = Arc::new(AppContext {
		cfg,
		panel_service: panel_service.clone(),
		shutdown_tx: shutdown_tx.clone(),
		online_clients,
	});

	// Start background tasks (BackgroundTasks creates its own dedicated runtime)
	let bg_handle = panel_service.start_background_tasks(ctx.clone());

	// Initialize and start server
	let server = server::Server::init(ctx.clone()).await?;

	// Wait for either server completion or shutdown signal
	tokio::select! {
		_ = server.start() => {
			info!("Server stopped");
		}
		_ = wait_for_shutdown_signal() => {
			info!("Shutdown signal received, stopping server...");
			// Send shutdown signal to all components
			let _ = shutdown_tx.send(());
		}
	}

	// Shutdown background tasks
	if let Some(handle) = bg_handle {
		handle.shutdown().await;
	}

	info!("Server shutdown complete");
	Ok(())
}

/// Wait for shutdown signal (SIGINT or SIGTERM)
async fn wait_for_shutdown_signal() {
	#[cfg(unix)]
	{
		use tokio::signal::unix::{SignalKind, signal};

		let mut sigint = signal(SignalKind::interrupt()).expect("Failed to register SIGINT handler");
		let mut sigterm = signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");

		tokio::select! {
			_ = sigint.recv() => {
				info!("Received SIGINT");
			}
			_ = sigterm.recv() => {
				info!("Received SIGTERM");
			}
		}
	}

	#[cfg(not(unix))]
	{
		tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl-C");
		info!("Received Ctrl-C");
	}
}

#[cfg(test)]
mod tests {
	use std::{collections::HashMap, sync::Arc};

	use moka::future::Cache;
	use tokio::sync::RwLock as AsyncRwLock;
	use uuid::Uuid;

	/// Test the OnlineClients data structure behavior
	/// We can't test with real QuinnConnection, so we use a mock type
	type MockConnection = Arc<String>; // Simple mock for testing
	type MockUserConnections = Arc<AsyncRwLock<HashMap<usize, MockConnection>>>;
	type MockOnlineClients = Cache<Uuid, MockUserConnections>;

	#[tokio::test]
	async fn test_online_clients_register_and_get() {
		let online_clients: MockOnlineClients = Cache::builder().build();
		let uuid = Uuid::new_v4();
		let conn_id: usize = 12345;
		let mock_conn = Arc::new("connection_1".to_string());

		// Register a connection
		let user_conns: MockUserConnections = online_clients
			.get_with(uuid, async { Arc::new(AsyncRwLock::new(HashMap::new())) })
			.await;
		user_conns.write().await.insert(conn_id, mock_conn.clone());

		// Verify the connection is registered
		let retrieved = online_clients.get(&uuid).await.unwrap();
		let conns = retrieved.read().await;
		assert_eq!(conns.len(), 1);
		assert!(conns.contains_key(&conn_id));
		assert_eq!(*conns.get(&conn_id).unwrap(), mock_conn);
	}

	#[tokio::test]
	async fn test_online_clients_multiple_connections_per_user() {
		let online_clients: MockOnlineClients = Cache::builder().build();
		let uuid = Uuid::new_v4();

		// Register multiple connections for the same user
		let user_conns: MockUserConnections = online_clients
			.get_with(uuid, async { Arc::new(AsyncRwLock::new(HashMap::new())) })
			.await;

		{
			let mut conns = user_conns.write().await;
			conns.insert(1, Arc::new("conn_1".to_string()));
			conns.insert(2, Arc::new("conn_2".to_string()));
			conns.insert(3, Arc::new("conn_3".to_string()));
		}

		// Verify all connections are registered
		let retrieved = online_clients.get(&uuid).await.unwrap();
		let conns = retrieved.read().await;
		assert_eq!(conns.len(), 3);
	}

	#[tokio::test]
	async fn test_online_clients_unregister() {
		let online_clients: MockOnlineClients = Cache::builder().build();
		let uuid = Uuid::new_v4();
		let conn_id: usize = 12345;

		// Register a connection
		let user_conns: MockUserConnections = online_clients
			.get_with(uuid, async { Arc::new(AsyncRwLock::new(HashMap::new())) })
			.await;
		user_conns.write().await.insert(conn_id, Arc::new("conn".to_string()));

		// Unregister the connection
		{
			let mut conns = user_conns.write().await;
			conns.remove(&conn_id);

			// If no more connections, remove user entry
			if conns.is_empty() {
				drop(conns);
				online_clients.remove(&uuid).await;
			}
		}

		// Verify the user entry is removed
		assert!(online_clients.get(&uuid).await.is_none());
	}

	#[tokio::test]
	async fn test_online_clients_unregister_keeps_other_connections() {
		let online_clients: MockOnlineClients = Cache::builder().build();
		let uuid = Uuid::new_v4();

		// Register multiple connections
		let user_conns: MockUserConnections = online_clients
			.get_with(uuid, async { Arc::new(AsyncRwLock::new(HashMap::new())) })
			.await;

		{
			let mut conns = user_conns.write().await;
			conns.insert(1, Arc::new("conn_1".to_string()));
			conns.insert(2, Arc::new("conn_2".to_string()));
		}

		// Unregister one connection
		{
			let mut conns = user_conns.write().await;
			conns.remove(&1);
			// Not empty, so don't remove user entry
			assert!(!conns.is_empty());
		}

		// Verify the other connection is still there
		let retrieved = online_clients.get(&uuid).await.unwrap();
		let conns = retrieved.read().await;
		assert_eq!(conns.len(), 1);
		assert!(conns.contains_key(&2));
	}

	#[tokio::test]
	async fn test_online_clients_multiple_users() {
		let online_clients: MockOnlineClients = Cache::builder().build();
		let uuid1 = Uuid::new_v4();
		let uuid2 = Uuid::new_v4();

		// Register connections for user 1
		let user1_conns: MockUserConnections = online_clients
			.get_with(uuid1, async { Arc::new(AsyncRwLock::new(HashMap::new())) })
			.await;
		user1_conns.write().await.insert(1, Arc::new("user1_conn".to_string()));

		// Register connections for user 2
		let user2_conns: MockUserConnections = online_clients
			.get_with(uuid2, async { Arc::new(AsyncRwLock::new(HashMap::new())) })
			.await;
		user2_conns.write().await.insert(2, Arc::new("user2_conn".to_string()));

		// Verify both users have their connections
		assert!(online_clients.get(&uuid1).await.is_some());
		assert!(online_clients.get(&uuid2).await.is_some());

		// Remove user1
		online_clients.remove(&uuid1).await;

		// Verify user1 is gone but user2 still exists
		assert!(online_clients.get(&uuid1).await.is_none());
		assert!(online_clients.get(&uuid2).await.is_some());
	}

	#[tokio::test]
	async fn test_kick_users_simulation() {
		let online_clients: MockOnlineClients = Cache::builder().build();
		let uuid = Uuid::new_v4();

		// Register multiple connections
		let user_conns: MockUserConnections = online_clients
			.get_with(uuid, async { Arc::new(AsyncRwLock::new(HashMap::new())) })
			.await;

		{
			let mut conns = user_conns.write().await;
			conns.insert(1, Arc::new("conn_1".to_string()));
			conns.insert(2, Arc::new("conn_2".to_string()));
			conns.insert(3, Arc::new("conn_3".to_string()));
		}

		// Simulate kick_users: iterate and "close" all connections
		if let Some(user_conns) = online_clients.get(&uuid).await {
			let conns = user_conns.read().await;
			let kicked_count = conns.len();

			// In real code, we would call conn.close() here
			for (conn_id, _conn) in conns.iter() {
				// Simulating: conn.close(KICK_ERROR_CODE, b"User removed");
				assert!(*conn_id >= 1 && *conn_id <= 3);
			}

			drop(conns);
			online_clients.remove(&uuid).await;

			assert_eq!(kicked_count, 3);
		}

		// Verify user is removed
		assert!(online_clients.get(&uuid).await.is_none());
	}

	#[tokio::test]
	async fn test_concurrent_register_same_user() {
		let online_clients: MockOnlineClients = Cache::builder().build();
		let uuid = Uuid::new_v4();

		// Simulate concurrent registrations for the same user
		let clients_clone = online_clients.clone();
		let uuid_clone = uuid;

		let handle1 = tokio::spawn(async move {
			let user_conns: MockUserConnections = clients_clone
				.get_with(uuid_clone, async { Arc::new(AsyncRwLock::new(HashMap::new())) })
				.await;
			user_conns.write().await.insert(1, Arc::new("conn_1".to_string()));
		});

		let clients_clone2 = online_clients.clone();
		let handle2 = tokio::spawn(async move {
			let user_conns: MockUserConnections = clients_clone2
				.get_with(uuid, async { Arc::new(AsyncRwLock::new(HashMap::new())) })
				.await;
			user_conns.write().await.insert(2, Arc::new("conn_2".to_string()));
		});

		handle1.await.unwrap();
		handle2.await.unwrap();

		// Both connections should be registered
		let retrieved = online_clients.get(&uuid).await.unwrap();
		let conns = retrieved.read().await;
		assert_eq!(conns.len(), 2);
	}
}
