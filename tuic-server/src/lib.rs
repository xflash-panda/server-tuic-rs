// Library interface for tuic-server
// This allows the server to be used as a library in integration tests

use std::{
	collections::HashMap,
	sync::{Arc, atomic::AtomicUsize},
};

use moka::future::Cache;
use tracing::{info, warn};
use uuid::Uuid;

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

pub struct AppContext {
	pub cfg:            Config,
	pub online_counter: HashMap<u64, AtomicUsize>,
	pub online_clients: Cache<Uuid, Arc<Cache<usize, compat::QuicClient>>>,
	pub traffic_stats:  HashMap<u64, (AtomicUsize, AtomicUsize)>,
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

	let mut online_counter = HashMap::new();
	for (_, uid) in cfg.users.iter() {
		online_counter.insert(*uid, AtomicUsize::new(0));
	}

	let mut traffic_stats = HashMap::new();
	for (_, uid) in cfg.users.iter() {
		traffic_stats.insert(*uid, (AtomicUsize::new(0), AtomicUsize::new(0)));
	}

	let ctx = Arc::new(AppContext {
		online_counter,
		online_clients: Cache::new(cfg.users.len() as u64),
		traffic_stats,
		cfg,
	});

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
