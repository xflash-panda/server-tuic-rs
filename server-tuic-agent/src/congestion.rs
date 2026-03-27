//! Wrapper around congestion controllers to work around upstream bugs.
//!
//! quinn-congestions BBR returns `pacing_rate = Some(0)` before bandwidth
//! estimation completes, which causes a division-by-zero panic in quinn's
//! pacer:   `Duration::from_secs_f64(bytes / 0) → Infinity → panic`
//!
//! This wrapper intercepts `metrics()` and filters out invalid pacing rates.

use std::{any::Any, sync::Arc, time::Instant};

use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;

/// Wraps a [`ControllerFactory`] to produce [`SafePacingController`]s.
pub struct SafePacingFactory {
	inner: Arc<dyn ControllerFactory + Send + Sync>,
}

impl SafePacingFactory {
	pub fn new(inner: Arc<dyn ControllerFactory + Send + Sync>) -> Self {
		Self { inner }
	}
}

impl ControllerFactory for SafePacingFactory {
	fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
		let inner = self.inner.clone().build(now, current_mtu);
		Box::new(SafePacingController { inner })
	}
}

/// Wraps any [`Controller`] and sanitizes `pacing_rate` in metrics.
struct SafePacingController {
	inner: Box<dyn Controller>,
}

impl Controller for SafePacingController {
	fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
		self.inner.on_sent(now, bytes, last_packet_number);
	}

	fn on_packet_sent(&mut self, now: Instant, bytes: u16, packet_number: u64) {
		self.inner.on_packet_sent(now, bytes, packet_number);
	}

	fn on_ack(&mut self, now: Instant, sent: Instant, bytes: u64, pn: u64, app_limited: bool, rtt: &RttEstimator) {
		self.inner.on_ack(now, sent, bytes, pn, app_limited, rtt);
	}

	fn on_end_acks(&mut self, now: Instant, in_flight: u64, app_limited: bool, largest_packet_num_acked: Option<u64>) {
		self.inner.on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
	}

	fn on_congestion_event(
		&mut self,
		now: Instant,
		sent: Instant,
		is_persistent_congestion: bool,
		is_ecn: bool,
		lost_bytes: u64,
		largest_lost: u64,
	) {
		self.inner
			.on_congestion_event(now, sent, is_persistent_congestion, is_ecn, lost_bytes, largest_lost);
	}

	fn on_packet_lost(&mut self, lost_bytes: u16, packet_number: u64, now: Instant) {
		self.inner.on_packet_lost(lost_bytes, packet_number, now);
	}

	fn on_spurious_congestion_event(&mut self) {
		self.inner.on_spurious_congestion_event();
	}

	fn on_mtu_update(&mut self, new_mtu: u16) {
		self.inner.on_mtu_update(new_mtu);
	}

	fn window(&self) -> u64 {
		self.inner.window()
	}

	fn metrics(&self) -> ControllerMetrics {
		let mut m = self.inner.metrics();
		// Filter out zero pacing_rate to prevent division-by-zero panic in quinn's
		// pacer
		if m.pacing_rate == Some(0) {
			m.pacing_rate = None;
		}
		m
	}

	fn clone_box(&self) -> Box<dyn Controller> {
		Box::new(SafePacingController {
			inner: self.inner.clone_box(),
		})
	}

	fn initial_window(&self) -> u64 {
		self.inner.initial_window()
	}

	fn into_any(self: Box<Self>) -> Box<dyn Any> {
		self.inner.into_any()
	}
}

#[cfg(test)]
mod tests {
	use quinn_congestions::bbr::BbrConfig;

	use super::*;

	/// Simulates the exact panic scenario: BBR startup with pacing_rate=0.
	/// Before the fix, this would panic with:
	///   "cannot convert float seconds to Duration: value is either too big or
	/// NaN"
	#[test]
	fn bbr_startup_pacing_rate_zero_does_not_panic() {
		let now = Instant::now();
		let mtu = 1200u16;

		// Build a real BBR controller — pacing_rate starts at 0
		let bbr_config = BbrConfig::default();
		let factory = Arc::new(SafePacingFactory::new(Arc::new(bbr_config)));
		let controller = factory.build(now, mtu);

		// Before any ACKs, BBR's pacing_rate is 0
		let metrics = controller.metrics();

		// The wrapper must filter Some(0) → None to prevent division-by-zero
		assert_ne!(
			metrics.pacing_rate,
			Some(0),
			"pacing_rate must not be Some(0) — would cause division-by-zero panic in quinn pacer"
		);
	}

	/// Verify that valid (non-zero) pacing_rate values pass through unchanged.
	#[test]
	fn nonzero_pacing_rate_passes_through() {
		// Use a mock controller that returns a known non-zero pacing_rate
		let controller = SafePacingController {
			inner: Box::new(MockController {
				pacing_rate: Some(100_000),
			}),
		};
		let metrics = controller.metrics();
		assert_eq!(metrics.pacing_rate, Some(100_000), "non-zero pacing_rate should pass through");
	}

	/// Verify None pacing_rate passes through as None.
	#[test]
	fn none_pacing_rate_passes_through() {
		let controller = SafePacingController {
			inner: Box::new(MockController { pacing_rate: None }),
		};
		let metrics = controller.metrics();
		assert_eq!(metrics.pacing_rate, None, "None pacing_rate should remain None");
	}

	/// Minimal mock controller for targeted metrics testing.
	struct MockController {
		pacing_rate: Option<u64>,
	}

	impl Controller for MockController {
		fn on_congestion_event(&mut self, _: Instant, _: Instant, _: bool, _: bool, _: u64, _: u64) {}

		fn on_mtu_update(&mut self, _: u16) {}

		fn window(&self) -> u64 {
			10000
		}

		fn metrics(&self) -> ControllerMetrics {
			let mut m = ControllerMetrics::default();
			m.pacing_rate = self.pacing_rate;
			m
		}

		fn clone_box(&self) -> Box<dyn Controller> {
			Box::new(MockController {
				pacing_rate: self.pacing_rate,
			})
		}

		fn initial_window(&self) -> u64 {
			10000
		}

		fn into_any(self: Box<Self>) -> Box<dyn Any> {
			self
		}
	}

	/// Verify SafePacingFactory produces wrapped controllers via clone_box too.
	#[test]
	fn cloned_controller_also_filters_zero_pacing_rate() {
		let now = Instant::now();
		let bbr_config = BbrConfig::default();
		let factory = Arc::new(SafePacingFactory::new(Arc::new(bbr_config)));
		let controller = factory.build(now, 1200);

		let cloned = controller.clone_box();
		let metrics = cloned.metrics();

		assert_ne!(
			metrics.pacing_rate,
			Some(0),
			"cloned controller must also filter zero pacing_rate"
		);
	}
}
