//! Statistics module for tracking user traffic and connections.

use std::sync::atomic::Ordering;

use crate::AppContext;

/// Record transmitted (upload) traffic for a user by UID
pub fn traffic_tx(ctx: &AppContext, uid: u64, bytes: usize) {
	if let Some((tx, _, _)) = ctx.traffic_stats.get(&uid) {
		tx.fetch_add(bytes, Ordering::Relaxed);
	}
}

/// Record received (download) traffic for a user by UID
pub fn traffic_rx(ctx: &AppContext, uid: u64, bytes: usize) {
	if let Some((_, rx, _)) = ctx.traffic_stats.get(&uid) {
		rx.fetch_add(bytes, Ordering::Relaxed);
	}
}

/// Increment request count for a user by UID
pub fn req_incr(ctx: &AppContext, uid: u64) {
	if let Some((_, _, req)) = ctx.traffic_stats.get(&uid) {
		req.fetch_add(1, Ordering::Relaxed);
	}
}

/// Get current traffic stats for a user by UID (tx, rx, conn)
pub fn get_traffic(ctx: &AppContext, uid: u64) -> Option<(usize, usize, usize)> {
	ctx.traffic_stats.get(&uid).map(|(tx, rx, conn)| {
		(tx.load(Ordering::Relaxed), rx.load(Ordering::Relaxed), conn.load(Ordering::Relaxed))
	})
}

/// Get all traffic stats
pub fn get_all_traffic(ctx: &AppContext) -> Vec<(u64, usize, usize, usize)> {
	ctx.traffic_stats
		.iter()
		.map(|(uid, (tx, rx, conn))| {
			(
				*uid,
				tx.load(Ordering::Relaxed),
				rx.load(Ordering::Relaxed),
				conn.load(Ordering::Relaxed),
			)
		})
		.collect()
}

/// Reset traffic stats for a user by UID and return previous values (tx, rx, conn)
pub fn reset_traffic(ctx: &AppContext, uid: u64) -> Option<(usize, usize, usize)> {
	ctx.traffic_stats.get(&uid).map(|(tx, rx, conn)| {
		(tx.swap(0, Ordering::Relaxed), rx.swap(0, Ordering::Relaxed), conn.swap(0, Ordering::Relaxed))
	})
}

/// Reset all traffic stats and return previous values
pub fn reset_all_traffic(ctx: &AppContext) -> Vec<(u64, usize, usize, usize)> {
	ctx.traffic_stats
		.iter()
		.map(|(uid, (tx, rx, conn))| {
			(
				*uid,
				tx.swap(0, Ordering::Relaxed),
				rx.swap(0, Ordering::Relaxed),
				conn.swap(0, Ordering::Relaxed),
			)
		})
		.collect()
}
