// Library interface for server
// This allows the server to be used as a library in integration tests

use std::{
	collections::HashMap,
	sync::{Arc, atomic::AtomicUsize},
};

use tokio::sync::{RwLock, broadcast};
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
	/// Traffic statistics per user, dynamically initialized on first access
	pub traffic_stats: RwLock<HashMap<i64, TrafficStats>>,
	pub panel_service: Arc<OptionalPanel>,
	pub shutdown_tx:   broadcast::Sender<()>,
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

	// Close panel service gracefully - always called regardless of success, failure, or panic
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

	// Traffic stats are initialized dynamically on first access
	let ctx = Arc::new(AppContext {
		traffic_stats: RwLock::new(HashMap::new()),
		cfg,
		panel_service: panel_service.clone(),
		shutdown_tx: shutdown_tx.clone(),
	});

	// Spawn panel service run task
	let panel_for_run = panel_service.clone();
	let ctx_for_panel = ctx.clone();
	let panel_handle = tokio::spawn(async move {
		if let Err(e) = panel_for_run.run(ctx_for_panel).await {
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
