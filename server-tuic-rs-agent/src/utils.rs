// Re-export common types from core
pub use tuic::UdpRelayMode;

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
