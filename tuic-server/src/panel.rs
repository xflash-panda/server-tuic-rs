use std::{sync::Arc, time::Duration};

use server_r_client::{ApiClient, Config as ApiConfig};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Trait defining the lifecycle of a panel service
#[async_trait::async_trait]
pub trait PanelService: Send + Sync {
	/// Initialize the service (called before server starts)
	async fn init(&self) -> eyre::Result<()>;

	/// Run the service (called while server is running)
	/// This method should be spawned as a background task
	async fn run(&self) -> eyre::Result<()>;

	/// Close the service (called when server is shutting down)
	async fn close(&self) -> eyre::Result<()>;
}

/// Configuration for the panel service
#[derive(Debug, Clone)]
pub struct PanelConfig {
	/// API host URL (e.g., "https://api.example.com")
	pub api_host: String,
	/// Authentication token
	pub token: String,
	/// Node ID for this server
	pub node_id: u32,
	/// Request timeout in seconds
	pub timeout: u64,
}

/// Panel service implementation using server-r-client
pub struct Panel {
	client: ApiClient,
	config: PanelConfig,
	running: RwLock<bool>,
}

impl Panel {
	/// Create a new Panel instance
	pub fn new(config: PanelConfig) -> eyre::Result<Self> {
		let api_config = ApiConfig::new(&config.api_host, &config.token)
			.with_timeout(Duration::from_secs(config.timeout));

		let client = ApiClient::new(api_config)
			.map_err(|e| eyre::eyre!("Failed to create API client: {}", e))?;

		Ok(Self {
			client,
			config,
			running: RwLock::new(false),
		})
	}

	/// Get a reference to the API client
	pub fn client(&self) -> &ApiClient {
		&self.client
	}

	/// Get the node ID
	pub fn node_id(&self) -> u32 {
		self.config.node_id
	}
}

#[async_trait::async_trait]
impl PanelService for Panel {
	async fn init(&self) -> eyre::Result<()> {
		info!("Panel service initializing...");
		// TODO: Implement user data fetching, node registration, etc.
		info!("Panel service initialized");
		Ok(())
	}

	async fn run(&self) -> eyre::Result<()> {
		{
			let mut running = self.running.write().await;
			*running = true;
		}

		info!("Panel service running...");

		// TODO: Implement periodic tasks:
		// - Fetch user data updates
		// - Submit traffic statistics
		// - Send heartbeat

		// For now, just wait until close is called
		loop {
			let running = self.running.read().await;
			if !*running {
				break;
			}
			drop(running);
			tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
		}

		info!("Panel service stopped");
		Ok(())
	}

	async fn close(&self) -> eyre::Result<()> {
		info!("Panel service closing...");

		{
			let mut running = self.running.write().await;
			*running = false;
		}

		// TODO: Implement cleanup:
		// - Submit final traffic statistics
		// - Unregister node

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
}

#[async_trait::async_trait]
impl PanelService for OptionalPanel {
	async fn init(&self) -> eyre::Result<()> {
		if let Some(panel) = &self.inner {
			panel.init().await
		} else {
			warn!("Panel service is disabled, skipping init");
			Ok(())
		}
	}

	async fn run(&self) -> eyre::Result<()> {
		if let Some(panel) = &self.inner {
			panel.run().await
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
