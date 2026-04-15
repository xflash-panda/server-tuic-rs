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
		info!("Panel service enabled, connecting to {}", panel_cfg.api_host);
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

/// Remove a connection from the online clients registry.
/// This is the logic extracted from Connection::unregister_client for
/// testability.
///
/// Note: We intentionally do NOT remove the cache entry when the inner map
/// becomes empty. Doing so would create a TOCTOU race: between dropping the
/// inner lock and calling cache.remove(), a concurrent register_client could
/// insert a new connection into the same entry — and remove() would silently
/// discard it. Empty entries are lightweight (Arc to empty HashMap) and will be
/// reused on reconnect. The kick_users path handles cleanup when users are
/// actually removed.
pub(crate) async fn unregister_from_online_clients(online_clients: &OnlineClients, uuid: &Uuid, conn_id: usize) {
	if let Some(user_conns) = online_clients.get(uuid).await {
		user_conns.write().await.remove(&conn_id);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// RED test: Proves the TOCTOU race in unregister_from_online_clients.
	///
	/// Scenario: conn_1 unregisters (sees empty inner map, drops lock, about to
	/// remove cache entry). Meanwhile conn_2 registers for the same user (goes
	/// into the same inner map). Then unregister removes the cache entry —
	/// conn_2's registration is silently lost.
	///
	/// We can't construct real QuinnConnection in tests, so we test with the
	/// cache at the entry-lifecycle level: if get_with returns the existing
	/// entry during the race window, and then remove() deletes that entry, any
	/// data added during the window is lost.
	#[tokio::test]
	async fn test_unregister_toctou_race() {
		let online_clients: OnlineClients = Cache::builder().build();
		let uuid = Uuid::new_v4();

		// Register: create cache entry with an empty inner map
		// (simulates state after conn_1 was removed from inner map — map is now empty)
		let _entry: UserConnections = online_clients
			.get_with(uuid, async { Arc::new(AsyncRwLock::new(HashMap::new())) })
			.await;

		// Simulate unregister_from_online_clients for conn_1 (id=1):
		// It already removed conn_1 from inner map, saw empty, dropped lock.
		// Now call the function which will see empty and remove the cache entry.
		unregister_from_online_clients(&online_clients, &uuid, 1).await;

		// RACE: conn_2 tries to register for the same user AFTER the remove.
		// In the real race, conn_2's get_with happens BETWEEN drop(lock) and remove().
		// Here we simulate it after — the entry is already gone from cache.
		let entry_after: UserConnections = online_clients
			.get_with(uuid, async { Arc::new(AsyncRwLock::new(HashMap::new())) })
			.await;

		// In the real race, entry_after would be the SAME Arc as _entry (get_with
		// returns existing). But because remove() already ran, get_with creates a
		// BRAND NEW Arc. The original Arc (which conn_2 would have written to) is
		// orphaned.
		//
		// This proves the race: even though no connections exist, the remove() creates
		// a window where a concurrent register can be lost.

		// To make this a concrete failure: verify that if we could have written
		// to the original entry, that data would be gone from the cache.
		// We prove this by checking ptr equality: they should be the same Arc if
		// no race occurred, but they're different because remove() intervened.
		assert!(
			Arc::ptr_eq(&_entry, &entry_after),
			"TOCTOU race: remove() destroyed the cache entry, causing get_with to create a new one. Any connection registered \
			 into the original entry is now orphaned."
		);
	}
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
