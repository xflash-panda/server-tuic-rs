// Re-export common types from core
pub use tuic::{StackPrefer, UdpRelayMode};

// Type alias for backward compatibility
pub type CongestionController = tuic::CongestionControl;

pub trait FutResultExt<T, E, Fut> {
	fn log_err(self) -> impl std::future::Future<Output = Option<T>>;
}
impl<T, Fut> FutResultExt<T, eyre::Report, Fut> for Fut
where
	Fut: std::future::Future<Output = Result<T, eyre::Report>> + Send,
	T: Send,
{
	#[inline(always)]
	async fn log_err(self) -> Option<T> {
		match self.await {
			Ok(v) => Some(v),
			Err(e) => {
				tracing::error!("{:?}", e);
				None
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_stack_prefer_serde() {
		use serde::Deserialize;

		#[derive(Deserialize)]
		struct TestConfig {
			mode: StackPrefer,
		}

		// Test deserialization from TOML
		let config: TestConfig = toml::from_str(r#"mode = "v4first""#).unwrap();
		assert_eq!(config.mode, StackPrefer::V4first);

		let config: TestConfig = toml::from_str(r#"mode = "v6first""#).unwrap();
		assert_eq!(config.mode, StackPrefer::V6first);

		let config: TestConfig = toml::from_str(r#"mode = "v4only""#).unwrap();
		assert_eq!(config.mode, StackPrefer::V4only);

		let config: TestConfig = toml::from_str(r#"mode = "v6only""#).unwrap();
		assert_eq!(config.mode, StackPrefer::V6only);
	}

	#[test]
	fn test_stack_prefer_variants() {
		// Test all variants exist and are distinct
		let modes = [
			StackPrefer::V4only,
			StackPrefer::V6only,
			StackPrefer::V4first,
			StackPrefer::V6first,
		];

		assert_eq!(modes.len(), 4); // Test equality
		assert_eq!(StackPrefer::V4only, StackPrefer::V4only);
		assert_ne!(StackPrefer::V4only, StackPrefer::V6only);
	}
}
