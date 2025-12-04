// Library interface for tuic-server
// This allows the server to be used as a library in integration tests

use std::{
	collections::HashMap,
	sync::{Arc, atomic::AtomicUsize},
};

use moka::future::Cache;
use uuid::Uuid;

pub mod acl;
pub mod compat;
pub mod config;
pub mod connection;
pub mod error;
pub mod io;
pub mod server;
pub mod stats;
pub mod tls;
pub mod utils;

pub use config::{Cli, Config, Control};

pub struct AppContext {
	pub cfg:            Config,
	pub online_counter: HashMap<u64, AtomicUsize>,
	pub online_clients: Cache<Uuid, Arc<Cache<usize, compat::QuicClient>>>,
	pub traffic_stats:  HashMap<u64, (AtomicUsize, AtomicUsize)>,
}

/// Run the TUIC server with the given configuration
pub async fn run(cfg: Config) -> eyre::Result<()> {
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
	let server = server::Server::init(ctx.clone()).await?;
	server.start().await;
	Ok(())
}
