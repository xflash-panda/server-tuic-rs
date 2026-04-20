//! Statistics module for tracking user traffic and connections.
//!
//! Delegates to panel-core's StatsCollector for lock-free traffic tracking.

use crate::AppContext;

/// Record transmitted (upload) traffic for a user by UID
pub fn traffic_tx(ctx: &AppContext, uid: i64, bytes: usize) {
	if let Some(collector) = ctx.panel_service.stats_collector() {
		collector.record_upload(uid, bytes as u64);
	}
}

/// Record received (download) traffic for a user by UID
pub fn traffic_rx(ctx: &AppContext, uid: i64, bytes: usize) {
	if let Some(collector) = ctx.panel_service.stats_collector() {
		collector.record_download(uid, bytes as u64);
	}
}

/// Increment request count for a user by UID
pub fn req_incr(ctx: &AppContext, uid: i64) {
	if let Some(collector) = ctx.panel_service.stats_collector() {
		collector.record_request(uid);
	}
}
