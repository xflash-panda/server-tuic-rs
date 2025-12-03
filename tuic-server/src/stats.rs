//! Statistics module for tracking user traffic.

use std::sync::atomic::Ordering;

use uuid::Uuid;

use crate::AppContext;

/// Record transmitted (upload) traffic for a user
pub fn traffic_tx(ctx: &AppContext, uuid: &Uuid, bytes: usize) {
	if let Some((tx, _)) = ctx.traffic_stats.get(uuid) {
		tx.fetch_add(bytes, Ordering::Relaxed);
	}
}

/// Record received (download) traffic for a user
pub fn traffic_rx(ctx: &AppContext, uuid: &Uuid, bytes: usize) {
	if let Some((_, rx)) = ctx.traffic_stats.get(uuid) {
		rx.fetch_add(bytes, Ordering::Relaxed);
	}
}

/// Get current traffic stats for a user (tx, rx)
pub fn get_traffic(ctx: &AppContext, uuid: &Uuid) -> Option<(usize, usize)> {
	ctx.traffic_stats
		.get(uuid)
		.map(|(tx, rx)| (tx.load(Ordering::Relaxed), rx.load(Ordering::Relaxed)))
}

/// Get all traffic stats
pub fn get_all_traffic(ctx: &AppContext) -> Vec<(Uuid, usize, usize)> {
	ctx.traffic_stats
		.iter()
		.map(|(uuid, (tx, rx))| (*uuid, tx.load(Ordering::Relaxed), rx.load(Ordering::Relaxed)))
		.collect()
}

/// Reset traffic stats for a user and return previous values (tx, rx)
pub fn reset_traffic(ctx: &AppContext, uuid: &Uuid) -> Option<(usize, usize)> {
	ctx.traffic_stats
		.get(uuid)
		.map(|(tx, rx)| (tx.swap(0, Ordering::Relaxed), rx.swap(0, Ordering::Relaxed)))
}

/// Reset all traffic stats and return previous values
pub fn reset_all_traffic(ctx: &AppContext) -> Vec<(Uuid, usize, usize)> {
	ctx.traffic_stats
		.iter()
		.map(|(uuid, (tx, rx))| (*uuid, tx.swap(0, Ordering::Relaxed), rx.swap(0, Ordering::Relaxed)))
		.collect()
}
