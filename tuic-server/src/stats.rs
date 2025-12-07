//! Statistics module for tracking user traffic and connections.
//!
//! Traffic stats are dynamically initialized on first access for each user,
//! avoiding pre-allocation and supporting dynamic user changes.

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::AppContext;

/// Ensure traffic stats entry exists for a user, creating it if necessary
async fn ensure_stats(ctx: &AppContext, uid: i64) {
	// Fast path: check if already exists with read lock
	{
		let stats = ctx.traffic_stats.read().await;
		if stats.contains_key(&uid) {
			return;
		}
	}
	// Slow path: acquire write lock and insert
	let mut stats = ctx.traffic_stats.write().await;
	stats
		.entry(uid)
		.or_insert_with(|| (AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0)));
}

/// Record transmitted (upload) traffic for a user by UID
pub async fn traffic_tx(ctx: &AppContext, uid: i64, bytes: usize) {
	ensure_stats(ctx, uid).await;
	let stats = ctx.traffic_stats.read().await;
	if let Some((tx, _, _)) = stats.get(&uid) {
		tx.fetch_add(bytes, Ordering::Relaxed);
	}
}

/// Record received (download) traffic for a user by UID
pub async fn traffic_rx(ctx: &AppContext, uid: i64, bytes: usize) {
	ensure_stats(ctx, uid).await;
	let stats = ctx.traffic_stats.read().await;
	if let Some((_, rx, _)) = stats.get(&uid) {
		rx.fetch_add(bytes, Ordering::Relaxed);
	}
}

/// Increment request count for a user by UID
pub async fn req_incr(ctx: &AppContext, uid: i64) {
	ensure_stats(ctx, uid).await;
	let stats = ctx.traffic_stats.read().await;
	if let Some((_, _, req)) = stats.get(&uid) {
		req.fetch_add(1, Ordering::Relaxed);
	}
}

/// Get current traffic stats for a user by UID (tx, rx, conn)
pub async fn get_traffic(ctx: &AppContext, uid: i64) -> Option<(usize, usize, usize)> {
	let stats = ctx.traffic_stats.read().await;
	stats.get(&uid).map(|(tx, rx, conn)| {
		(tx.load(Ordering::Relaxed), rx.load(Ordering::Relaxed), conn.load(Ordering::Relaxed))
	})
}

/// Get all traffic stats
pub async fn get_all_traffic(ctx: &AppContext) -> Vec<(i64, usize, usize, usize)> {
	let stats = ctx.traffic_stats.read().await;
	stats
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
pub async fn reset_traffic(ctx: &AppContext, uid: i64) -> Option<(usize, usize, usize)> {
	let stats = ctx.traffic_stats.read().await;
	stats.get(&uid).map(|(tx, rx, conn)| {
		(tx.swap(0, Ordering::Relaxed), rx.swap(0, Ordering::Relaxed), conn.swap(0, Ordering::Relaxed))
	})
}

/// Reset all traffic stats and return previous values
pub async fn reset_all_traffic(ctx: &AppContext) -> Vec<(i64, usize, usize, usize)> {
	let stats = ctx.traffic_stats.read().await;
	stats
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
