// Library interface for tuic-server
// This allows the server to be used as a library in integration tests

use std::{
	collections::HashMap,
	sync::{Arc, atomic::AtomicUsize},
};

use tracing::{info, warn};

pub mod acl;
pub mod compat;
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

	let mut traffic_stats = HashMap::new();
	for (_, uid) in cfg.users.iter() {
		traffic_stats.insert(*uid, (AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0)));
	}

	let ctx = Arc::new(AppContext { traffic_stats, cfg });

	// Spawn panel service run task
	let panel_for_run = panel_service.clone();
	let panel_handle = tokio::spawn(async move {
		if let Err(e) = panel_for_run.run().await {
			tracing::error!("Panel service error: {}", e);
		}
	});

	// Initialize and start server
	let server = server::Server::init(ctx.clone()).await?;
	server.start().await;

	// Close panel service when server stops
	panel_service.close().await?;

	// Wait for panel task to finish
	let _ = panel_handle.await;

	Ok(())
}
