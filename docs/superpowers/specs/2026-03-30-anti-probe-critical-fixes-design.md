# Anti-Probe Critical Fixes Design

**Date:** 2026-03-30
**Status:** Draft
**Scope:** server-tuic anti_probe=true mode only

## Problem

GFW detects TUIC servers within ~12 hours via active probing. The server has H3 mimicry defenses (fake SETTINGS, QPACK streams, 404 responses), but three critical fingerprints remain:

1. **auth_timeout closes connections after 3s** — real H3 servers keep idle connections 30s+
2. **QUIC transport parameters are non-standard** — send_window=16MB, receive_window=8MB, no keep_alive
3. **No GOAWAY frame before close** — real H3 servers send GOAWAY (0x07) before closing

## Constraints

- All changes gated behind `anti_probe=true` only
- Must not break TUIC client functionality (ClashMeta sends auth within milliseconds of handshake)
- Must not break existing anti_probe=false behavior

## Design

### Fix 1: auth_timeout behavior (`connection/mod.rs`)

**Current:** `timeout_authenticate()` sleeps for `auth_timeout` (3s), then calls `self.close()` unconditionally.

**New behavior when anti_probe=true:**
- `timeout_authenticate()` sleeps for `auth_timeout`
- If not authenticated, **do NOT close** — instead log and let `max_idle_timeout` (30s) handle natural closure
- Before `max_idle_timeout` closes the connection, send GOAWAY (see Fix 3)
- If anti_probe=false: existing behavior unchanged (close after auth_timeout)

**Why this is safe:** ClashMeta sends auth in <100ms. Any connection not authenticated after 3s is definitively a probe or scanner. We just don't reveal this knowledge by closing early.

**Impact on TUIC clients:** Zero. Authenticated connections are unaffected. Only unauthenticated (probe) connections stay open longer.

### Fix 2: Transport parameters (`server.rs`, `config.rs`)

When `anti_probe=true`, override transport parameters to match Caddy h3 defaults:

| Parameter | Current | New (anti_probe) | Caddy Reference |
|-----------|---------|-------------------|-----------------|
| `send_window` | 16MB | 1.5MB (1572864) | Caddy default |
| `stream_receive_window` | 8MB | 1MB (1048576) | Caddy default |
| `keep_alive_interval` | None | 15s | Common H3 behavior |

These are initial values. QUIC flow control dynamically scales windows during active transfers, so sustained throughput impact is minimal — the connection ramps up quickly once data flows.

When `anti_probe=false`: existing values unchanged.

**Implementation:** Add `anti_probe_send_window()`, `anti_probe_receive_window()`, `anti_probe_keep_alive_interval()` methods to `ExperimentalConfig`, used in `server.rs` TransportConfig setup.

### Fix 3: GOAWAY frame before close (`anti_probe.rs`, `connection/mod.rs`)

**New functions in `anti_probe.rs`:**
- `build_h3_goaway_frame(last_stream_id: u64) -> Vec<u8>` — builds H3 GOAWAY frame (type 0x07, varint-encoded stream ID)
- `send_goaway_before_close(conn: &quinn::Connection)` — sends GOAWAY on the H3 control stream, then waits briefly before close

**Integration:** When anti_probe=true, the connection close path (both auth_timeout expiry for anti_probe=false and idle timeout natural close) sends GOAWAY first.

GOAWAY frame format per RFC 9114 section 5.2:
```
GOAWAY Frame {
  Type (i) = 0x07,
  Length (i),
  Stream ID (i),
}
```

We send `last_stream_id = 0` (no streams were processed for probe connections).

**Challenge:** GOAWAY must be sent on the **same control stream** opened earlier by `send_h3_probe_response()`. We need to store the control stream's `SendStream` handle in the connection state for later use.

**Implementation:**
- Store the H3 control stream `SendStream` in `Connection` struct (wrapped in `Option<Mutex<SendStream>>`)
- `send_h3_probe_response()` returns the control stream handle instead of dropping it
- On close, write GOAWAY to the stored control stream, then close connection

## Files Changed

| File | Changes |
|------|---------|
| `server-tuic-agent/src/connection/mod.rs` | Modify `timeout_authenticate()`, store control stream handle |
| `server-tuic-agent/src/connection/anti_probe.rs` | Add `build_h3_goaway_frame()`, `send_goaway_before_close()` |
| `server-tuic-agent/src/server.rs` | Apply anti_probe transport params |
| `server-tuic-agent/src/config.rs` | Add anti_probe window/keepalive config methods |

## Test Plan

### Unit Tests (`anti_probe.rs`)

1. `test_build_h3_goaway_frame_zero` — GOAWAY with stream_id=0 produces correct bytes
2. `test_build_h3_goaway_frame_nonzero` — GOAWAY with stream_id=4 produces correct bytes
3. `test_build_h3_goaway_frame_large_id` — GOAWAY with large stream ID uses multi-byte varint

### Unit Tests (`config.rs`)

4. `test_anti_probe_send_window` — returns 1572864 when anti_probe=true
5. `test_anti_probe_receive_window` — returns 1048576 when anti_probe=true
6. `test_anti_probe_keep_alive` — returns 15s when anti_probe=true
7. `test_default_windows_when_anti_probe_off` — returns original values when anti_probe=false

### Integration Tests (tuic-probe)

8. Add new probe checks to tuic-probe to verify fixes:
   - Idle timeout check should see 30s+ (not 3s)
   - Transport params should match H3 ranges
   - GOAWAY should be received before connection close

## Verification

After deploying:
1. Run tuic-probe against the updated server — all 3 fixed checks should now PASS
2. Connect with ClashMeta client — verify normal proxy functionality works
3. Monitor server survival time — expect significant increase from ~12h baseline
