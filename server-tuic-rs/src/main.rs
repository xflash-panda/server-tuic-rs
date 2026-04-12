use std::process;

use clap::Parser;
use server_tuic_rs::config::{Cli, Control, parse_config};
#[cfg(feature = "jemallocator")]
use tikv_jemallocator::Jemalloc;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt::time::LocalTime, layer::SubscriberExt, util::SubscriberInitExt};

#[cfg(feature = "jemallocator")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> eyre::Result<()> {
	// Install default crypto provider for rustls (required by server-client-rs)
	#[cfg(feature = "ring")]
	let _ = rustls::crypto::ring::default_provider().install_default();
	#[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

	let cli = Cli::parse();
	let cfg = match parse_config(cli).await {
		Ok(cfg) => cfg,
		Err(err) => {
			// Check if it's a Control error (Help or Version)
			if let Some(control) = err.downcast_ref::<Control>() {
				println!("{}", control);
				process::exit(0);
			}
			return Err(err);
		}
	};
	let filter = tracing_subscriber::filter::Targets::new()
		.with_targets(vec![
			("tuic", cfg.log_mode),
			("tuic_quinn", cfg.log_mode),
			("server_tuic_rs", cfg.log_mode),
		])
		.with_default(LevelFilter::INFO);
	let registry = tracing_subscriber::registry();
	registry
		.with(filter)
		.with(tracing_subscriber::fmt::layer().with_target(true).with_timer(LocalTime::new(
			time::format_description::parse("[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]").unwrap(),
		)))
		.try_init()?;

	server_tuic_rs::run(cfg).await?;

	Ok(())
}
