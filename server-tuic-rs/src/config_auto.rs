//! Automatic computation of `max_connections` from system resources.
//!
//! Constants are derived from this server's specific implementation:
//!   - QUIC over a single shared UDP socket — inbound fd cost is amortized
//!     across all clients, only outbound fds count per connection
//!   - rustls + aws-lc-rs (AES-NI for AES-GCM ciphersuites) inside QUIC, plus
//!     per-packet header protection / pacing / loss recovery
//!   - Stream relay buffers 16+16 KB per active stream (`io::BUFFER_SIZE`)
//!   - `INIT_CONCURRENT_STREAMS = 32` per connection (auto-doubled under load)
//!   - Default `send_window = 16 MB`, `receive_window = 8 MB` (peak, not
//!     steady)

use std::str::FromStr;

use tracing::warn;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum MaxConnections {
	#[default]
	Auto,
	Fixed(usize),
}

impl FromStr for MaxConnections {
	type Err = String;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.eq_ignore_ascii_case("auto") {
			return Ok(Self::Auto);
		}
		let n = s
			.parse::<usize>()
			.map_err(|_| format!("Invalid max_connections '{s}'. Use 'auto' or a positive integer"))?;
		if n == 0 {
			return Err(format!(
				"Invalid max_connections '{s}'. Must be 'auto' or a positive integer (>= 1)"
			));
		}
		Ok(Self::Fixed(n))
	}
}

/// Sustained throughput per CPU core (Mbps).
///
/// QUIC adds significant per-packet overhead vs. plain TLS-over-TCP — header
/// protection, per-packet AEAD seal/open, packet pacing, loss recovery, RTT
/// estimation, and the inherent inefficiency of many small UDP packets vs.
/// few large TCP segments. End-to-end realistic throughput on x86_64 with
/// AES-NI is **~1 Gbps/core**, lower than trojan/anytls's 1.5 Gbps/core.
///
/// TODO(arch): tuned for x86_64 with AES-NI. ARM cores with crypto-extensions
/// (ARMv8 Crypto) are in the same ballpark; ARM cores without can be 2–3×
/// slower.
const PER_CORE_MBPS: u64 = 1000;

/// Average per-user bandwidth assumption (Kbps).
///
/// Mixed proxy traffic (mobile + desktop, web + occasional video) averages
/// 100~500 Kbps per active user. 200 Kbps is a middle-of-the-road default.
const PER_USER_KBPS: u64 = 200;

/// Per-connection user-space + kernel memory cost (KB).
///
/// Steady-state breakdown (one authenticated QUIC connection with ~1-2
/// active streams, code-traceable):
///
/// - quinn QUIC connection state (TLS 1.3 + AEAD + packet number spaces): ~50
///   KB
/// - BBR/Cubic congestion controller state: ~10 KB
/// - In-flight buffers (well below `send/receive_window` for typical BDP): ~50
///   KB
/// - 1-2 active streams × `io::copy_io` 16+16 KB relay buffers: 32-64 KB
/// - 1-2 outbound TcpStream + kernel TCP buffers: 30-60 KB
/// - 2 always-on tasks (`timeout_authenticate`, `collect_garbage`): ~2 KB
/// - HashMaps for udp_sessions / per-stream task overhead: ~5 KB
///
/// Total ≈ 300 KB / connection (active steady state). Heavier than
/// trojan/mieru because each TUIC "connection" multiplexes multiple streams
/// (one user device can have several proxied requests in flight).
///
/// Note: a heavily-loaded connection can in principle hit
/// `send_window + receive_window = 24 MB`, but that's flow-control
/// headroom, not steady-state allocation. BDP for typical 200 Kbps traffic
/// at 100 ms RTT is ~2.5 KB.
const PER_SESSION_KB: u64 = 300;

/// Fraction of total RAM (in percent) reserved as the connection-state budget.
/// The remaining 50% covers kernel UDP/TCP buffers, panel client, geosite,
/// logs.
const MEM_BUDGET_PCT: u64 = 50;

/// File descriptors reserved for non-connection use (logs, panel HTTP, DNS).
/// On boxes with a small `RLIMIT_NOFILE` this is capped to a quarter of the
/// limit so a low rlimit doesn't drive `fd_cap` to zero.
const FD_RESERVE_DEFAULT: u64 = 1024;

/// Average file descriptors consumed per QUIC connection.
///
/// TUIC uses **one shared UDP socket** for all clients (`server.rs`), so the
/// inbound fd cost is amortized to zero per connection. Each active stream
/// opens 1 outbound TCP/UDP socket; a typical authenticated client has 1-3
/// streams in flight. 3 is a conservative average.
const FD_PER_SESSION: u64 = 3;

/// Pure function that computes `max_connections` from system resources.
///
/// Formula:
/// ```text
/// auto = min(
///     cpus * PER_CORE_MBPS * 1000 / PER_USER_KBPS,           // CPU throughput
///     total_mem_kb * MEM_BUDGET_PCT / 100 / PER_SESSION_KB,  // memory
///     (nofile_soft - reserve) / FD_PER_SESSION,              // file descriptors
/// )
/// ```
/// where `reserve = min(FD_RESERVE_DEFAULT, nofile_soft / 4)`.
///
/// The minimum result is 1 — any caller passing a degenerate input still
/// receives a value safe to feed into `Semaphore::new`.
pub fn compute_auto(cpus: usize, total_mem_kb: u64, nofile_soft: u64) -> AutoBreakdown {
	let cpus = cpus.max(1) as u64;

	let cpu_cap = cpus.saturating_mul(PER_CORE_MBPS).saturating_mul(1000) / PER_USER_KBPS;

	let mem_cap = total_mem_kb.saturating_mul(MEM_BUDGET_PCT) / 100 / PER_SESSION_KB;

	let fd_reserve = FD_RESERVE_DEFAULT.min(nofile_soft / 4);
	let fd_cap = nofile_soft.saturating_sub(fd_reserve) / FD_PER_SESSION;

	let raw = cpu_cap.min(mem_cap).min(fd_cap);
	let value = (raw.max(1)) as usize;

	let limiting = if cpu_cap <= mem_cap && cpu_cap <= fd_cap {
		Limit::Cpu
	} else if mem_cap <= fd_cap {
		Limit::Memory
	} else {
		Limit::FileDescriptors
	};

	AutoBreakdown {
		value,
		cpu_cap,
		mem_cap,
		fd_cap,
		limiting,
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
	Cpu,
	Memory,
	FileDescriptors,
}

impl Limit {
	pub fn as_str(&self) -> &'static str {
		match self {
			Limit::Cpu => "cpu",
			Limit::Memory => "memory",
			Limit::FileDescriptors => "fd",
		}
	}
}

#[derive(Debug, Clone, Copy)]
pub struct AutoBreakdown {
	pub value:    usize,
	pub cpu_cap:  u64,
	pub mem_cap:  u64,
	pub fd_cap:   u64,
	pub limiting: Limit,
}

/// Returns true if a user-supplied fixed `max_connections` exceeds any of
/// the auto-derived safety caps (CPU throughput, memory budget, file
/// descriptors). Pure helper so the diagnostic warning is unit-testable.
pub fn fixed_exceeds_auto_cap(value: usize, bd: &AutoBreakdown) -> bool {
	let v = value as u64;
	v > bd.cpu_cap || v > bd.mem_cap || v > bd.fd_cap
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveMode {
	Auto,
	Fixed,
}

#[derive(Debug, Clone, Copy)]
pub struct ResolvedMaxConnections {
	pub value:        usize,
	pub mode:         ResolveMode,
	/// Always populated. For `Fixed`, this is the auto-derived reference cap
	/// against which the user-supplied value can be compared for diagnostics.
	pub breakdown:    AutoBreakdown,
	pub cpus:         usize,
	pub total_mem_kb: u64,
	pub nofile_soft:  u64,
}

/// Resolve a `MaxConnections` spec to a concrete value, querying the host
/// in both modes so the caller can log/compare against the auto-derived cap.
/// Always succeeds; falls back to safe defaults when host queries fail.
pub fn resolve(spec: MaxConnections) -> ResolvedMaxConnections {
	// available_parallelism() reads the CPU affinity mask on Linux, NOT the
	// cgroup CPU quota. In a container with cpu_quota set (e.g. K8s
	// `cpus: 500m`) this overestimates capacity — operators in such
	// environments should pass an explicit fixed value.
	let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);

	// 4 GB fallback when total memory can't be queried (non-Linux dev hosts).
	// Production target is Linux where the real value is always available;
	// surfacing the fallback prevents silent miscalibration of the auto cap.
	let total_mem_kb = total_memory_kb().unwrap_or_else(|| {
		warn!("total_memory_kb unavailable on this platform, using 4 GB fallback for auto cap");
		4 * 1024 * 1024
	});
	let nofile_soft = nofile_soft_limit().unwrap_or_else(|| {
		warn!("RLIMIT_NOFILE unavailable on this platform, using 65536 fallback for auto cap");
		65_536
	});

	let breakdown = compute_auto(cpus, total_mem_kb, nofile_soft);

	let (value, mode) = match spec {
		MaxConnections::Fixed(n) => (n, ResolveMode::Fixed),
		MaxConnections::Auto => (breakdown.value, ResolveMode::Auto),
	};

	ResolvedMaxConnections {
		value,
		mode,
		breakdown,
		cpus,
		total_mem_kb,
		nofile_soft,
	}
}

#[cfg(target_os = "linux")]
fn total_memory_kb() -> Option<u64> {
	// SAFETY: sysconf is async-signal-safe and side-effect-free.
	let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
	let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
	if pages > 0 && page_size > 0 {
		Some((pages as u64).saturating_mul(page_size as u64) / 1024)
	} else {
		None
	}
}

#[cfg(all(unix, not(target_os = "linux")))]
fn total_memory_kb() -> Option<u64> {
	// macOS/BSD don't expose _SC_PHYS_PAGES.  Production target is Linux,
	// so a None here just means dev builds use the safe fallback.
	None
}

#[cfg(not(unix))]
fn total_memory_kb() -> Option<u64> {
	None
}

#[cfg(unix)]
fn nofile_soft_limit() -> Option<u64> {
	let mut rl = libc::rlimit {
		rlim_cur: 0,
		rlim_max: 0,
	};
	// SAFETY: getrlimit fills the rlimit struct; no aliasing concerns.
	let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) };
	if ret == 0 { Some(rl.rlim_cur) } else { None }
}

#[cfg(not(unix))]
fn nofile_soft_limit() -> Option<u64> {
	None
}

#[cfg(test)]
mod tests {
	use super::*;

	fn mb_to_kb(mb: u64) -> u64 {
		mb * 1024
	}

	fn gb_to_kb(gb: u64) -> u64 {
		gb * 1024 * 1024
	}

	#[test]
	fn parses_auto_case_insensitive() {
		assert_eq!("auto".parse::<MaxConnections>().unwrap(), MaxConnections::Auto);
		assert_eq!("AUTO".parse::<MaxConnections>().unwrap(), MaxConnections::Auto);
	}

	#[test]
	fn parses_fixed_integer() {
		assert_eq!("5000".parse::<MaxConnections>().unwrap(), MaxConnections::Fixed(5000));
	}

	#[test]
	fn zero_is_rejected() {
		assert!("0".parse::<MaxConnections>().is_err());
	}

	#[test]
	fn rejects_garbage() {
		assert!("xyz".parse::<MaxConnections>().is_err());
		assert!("-1".parse::<MaxConnections>().is_err());
	}

	#[test]
	fn default_is_auto() {
		assert_eq!(MaxConnections::default(), MaxConnections::Auto);
	}

	#[test]
	fn one_cpu_two_gb_is_memory_bound() {
		// CPU = 1 * 1000 * 1000 / 200 = 5000
		// mem = 2*1024*1024 * 50 / 100 / 300 ≈ 3495
		// fd  = (65536 - 1024) / 3 ≈ 21504
		// min = 3495, memory-bound
		let bd = compute_auto(1, gb_to_kb(2), 65_536);
		assert_eq!(bd.limiting, Limit::Memory);
		assert!(bd.value >= 3_400 && bd.value <= 3_600, "got {}", bd.value);
	}

	#[test]
	fn two_cpu_four_gb_is_memory_bound() {
		// CPU = 10000
		// mem ≈ 6990
		// min = 6990, memory-bound
		let bd = compute_auto(2, gb_to_kb(4), 65_536);
		assert_eq!(bd.limiting, Limit::Memory);
		assert!(bd.value >= 6_800 && bd.value <= 7_100, "got {}", bd.value);
	}

	#[test]
	fn large_cpu_huge_ram_is_cpu_bound() {
		// CPU = 4 * 1000 * 1000 / 200 = 20000
		// mem = 16*1024*1024 * 50 / 100 / 300 ≈ 27962
		// fd  ≈ 21504
		// min = 20000, CPU-bound (CPU < FD < mem)
		let bd = compute_auto(4, gb_to_kb(16), 65_536);
		assert_eq!(bd.limiting, Limit::Cpu);
		assert_eq!(bd.value, 20_000);
	}

	#[test]
	fn many_cores_small_ram_is_memory_bound() {
		let bd = compute_auto(16, gb_to_kb(2), 65_536);
		assert_eq!(bd.limiting, Limit::Memory);
		assert!(bd.value <= 3_600);
	}

	#[test]
	fn small_rlimit_uses_adaptive_reserve() {
		// nofile=512: reserve = min(1024, 128) = 128
		// fd_cap = (512 - 128) / 3 = 128
		let bd = compute_auto(8, gb_to_kb(16), 512);
		assert_eq!(bd.limiting, Limit::FileDescriptors);
		assert_eq!(bd.fd_cap, 128);
		assert_eq!(bd.value, 128);
	}

	#[test]
	fn tight_fd_limit_binds() {
		// nofile=4096: reserve = min(1024, 1024) = 1024
		// fd_cap = (4096 - 1024) / 3 = 1024
		let bd = compute_auto(8, gb_to_kb(16), 4096);
		assert_eq!(bd.limiting, Limit::FileDescriptors);
		assert_eq!(bd.value, 1024);
	}

	#[test]
	fn tiny_box_reports_actual_value_not_floor() {
		// 32 MB → mem_cap = 32*1024*0.5/300 = 54
		let bd = compute_auto(1, mb_to_kb(32), 65_536);
		assert_eq!(bd.limiting, Limit::Memory);
		assert_eq!(bd.value, bd.mem_cap as usize);
		assert!(bd.value < 100, "got {}", bd.value);
	}

	#[test]
	fn degenerate_zero_inputs_floor_to_one() {
		let bd = compute_auto(1, 0, 0);
		assert_eq!(bd.value, 1);
	}

	#[test]
	fn zero_cpus_treated_as_one() {
		let bd0 = compute_auto(0, gb_to_kb(2), 65_536);
		let bd1 = compute_auto(1, gb_to_kb(2), 65_536);
		assert_eq!(bd0.cpu_cap, bd1.cpu_cap);
	}

	#[test]
	fn fixed_under_caps_does_not_warn() {
		let bd = compute_auto(2, gb_to_kb(4), 65_536);
		assert!(!fixed_exceeds_auto_cap(100, &bd));
	}

	#[test]
	fn fixed_over_any_cap_warns() {
		let bd = compute_auto(2, gb_to_kb(4), 65_536);
		// mem_cap ≈ 6990 — anything well above triggers
		assert!(fixed_exceeds_auto_cap(50_000, &bd));
	}

	#[test]
	fn resolve_auto_smokes() {
		let r = resolve(MaxConnections::Auto);
		assert_eq!(r.mode, ResolveMode::Auto);
		assert!(r.value >= 1);
		assert!(r.cpus >= 1);
		let bd = r.breakdown;
		assert_eq!(r.value, bd.value);
		assert!(bd.value as u64 <= bd.cpu_cap);
		assert!(bd.value as u64 <= bd.mem_cap);
		assert!(bd.value as u64 <= bd.fd_cap);
	}

	#[test]
	fn resolve_fixed_passes_value_through() {
		let r = resolve(MaxConnections::Fixed(1234));
		assert_eq!(r.value, 1234);
		assert_eq!(r.mode, ResolveMode::Fixed);
		assert!(r.breakdown.value >= 1);
	}
}
