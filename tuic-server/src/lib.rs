// Library interface for tuic-server
// This allows the server to be used as a library in integration tests

use std::{
	collections::HashMap,
	sync::{Arc, atomic::AtomicUsize},
};

use tokio::sync::broadcast;
use tracing::{error, info, warn};

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
pub use panel::{OptionalPanel, Panel, PanelService};

/// Traffic statistics tuple: (tx_bytes, rx_bytes, connection_count)
pub type TrafficStats = (AtomicUsize, AtomicUsize, AtomicUsize);

pub struct AppContext {
	pub cfg:           Config,
	pub traffic_stats: HashMap<u64, TrafficStats>,
	pub shutdown_tx:   broadcast::Sender<()>,
}

/// Run the TUIC server with the given configuration
pub async fn run(cfg: Config) -> eyre::Result<()> {
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
	panel_service.init().await?;

	// Use inner function to ensure panel_service.close() is always called
	let result = run_inner(panel_service.clone(), cfg).await;

	// Close panel service gracefully - always called regardless of success or failure
	info!("Closing panel service...");
	if let Err(e) = panel_service.close().await {
		error!("Failed to close panel service: {}", e);
	}

	result
}

/// Inner run function that can return early on error
async fn run_inner(panel_service: Arc<OptionalPanel>, cfg: Config) -> eyre::Result<()> {
	let mut traffic_stats = HashMap::new();
	for (_, uid) in cfg.users.iter() {
		traffic_stats.insert(*uid, (AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0)));
	}

	// Create shutdown signal channel
	let (shutdown_tx, _) = broadcast::channel::<()>(1);

	let ctx = Arc::new(AppContext {
		traffic_stats,
		cfg,
		shutdown_tx: shutdown_tx.clone(),
	});

	// Spawn panel service run task
	let panel_for_run = panel_service.clone();
	let panel_handle = tokio::spawn(async move {
		if let Err(e) = panel_for_run.run().await {
			error!("Panel service error: {}", e);
		}
	});

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

	// Wait for panel task to finish
	let _ = panel_handle.await;

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
		tokio::signal::ctrl_c()
			.await
			.expect("Failed to listen for Ctrl-C");
		info!("Received Ctrl-C");
	}
}
