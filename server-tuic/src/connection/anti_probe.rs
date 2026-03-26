//! Anti-probe defense module
//!
//! Generates fake HTTP/3 frames to disguise the TUIC server as an HTTP/3
//! server, preventing active probing tools from identifying the protocol.

/// HTTP/3 Control Stream type
const H3_STREAM_TYPE_CONTROL: u8 = 0x00;

/// HTTP/3 SETTINGS frame type
const H3_FRAME_TYPE_SETTINGS: u8 = 0x04;

/// HTTP/3 GOAWAY frame type
const H3_FRAME_TYPE_GOAWAY: u8 = 0x07;

/// Build a fake HTTP/3 SETTINGS frame payload for a server-initiated
/// uni-stream.
///
/// The probe tool reads the first byte of server-initiated uni-streams:
/// - If first byte is `0x04` (SETTINGS frame type) → concludes "Not TUIC"
/// - If first byte is `0x05` (TUIC version) → concludes "TUIC detected"
///
/// We send the SETTINGS frame type directly (not prefixed with control stream
/// type) because the probe checks `buf[0] == 0x04`.
///
/// Returns bytes that look like a minimal HTTP/3 SETTINGS frame.
pub fn build_h3_settings_frame() -> Vec<u8> {
	// HTTP/3 SETTINGS frame:
	// - Frame type: 0x04
	// - Frame length: variable-length integer (number of settings bytes)
	// - Settings: key-value pairs as variable-length integers
	//
	// We include realistic settings that a real HTTP/3 server would send:
	// - SETTINGS_MAX_FIELD_SECTION_SIZE (0x06) = 16384
	// - SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01) = 0
	// - SETTINGS_QPACK_BLOCKED_STREAMS (0x07) = 0
	let mut buf = Vec::with_capacity(16);

	// Control stream type (0x00) - this is what a real HTTP/3 server sends first
	buf.push(H3_STREAM_TYPE_CONTROL);

	// SETTINGS frame
	buf.push(H3_FRAME_TYPE_SETTINGS); // frame type
	buf.push(0x09); // frame length: 9 bytes

	// SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01) = 0
	buf.push(0x01);
	buf.push(0x00);

	// SETTINGS_QPACK_BLOCKED_STREAMS (0x07) = 0
	buf.push(0x07);
	buf.push(0x00);

	// SETTINGS_MAX_FIELD_SECTION_SIZE (0x06) = 16384 (0x4000 in variable-length int
	// = 0x80, 0x00, 0x40, 0x00) Actually use simple 2-byte encoding: 0x40, 0x00
	// means 16384 in QUIC varint
	buf.push(0x06);
	buf.extend_from_slice(&[0x80, 0x00, 0x40, 0x00]); // 16384 as 4-byte varint

	buf
}

/// Build a fake HTTP/3 GOAWAY frame.
/// Sent before closing connection to mimic HTTP/3 graceful shutdown.
pub fn build_h3_goaway_frame() -> Vec<u8> {
	let mut buf = Vec::with_capacity(4);
	buf.push(H3_FRAME_TYPE_GOAWAY); // frame type
	buf.push(0x01); // frame length: 1 byte
	buf.push(0x00); // stream id: 0
	buf
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_h3_settings_frame_starts_with_control_stream_type() {
		let frame = build_h3_settings_frame();
		assert!(!frame.is_empty());
		// First byte should be H3 control stream type (0x00)
		assert_eq!(
			frame[0], H3_STREAM_TYPE_CONTROL,
			"first byte must be control stream type 0x00"
		);
	}

	#[test]
	fn test_h3_settings_frame_contains_settings_type() {
		let frame = build_h3_settings_frame();
		// Second byte should be SETTINGS frame type (0x04)
		assert_eq!(
			frame[1], H3_FRAME_TYPE_SETTINGS,
			"second byte must be SETTINGS frame type 0x04"
		);
	}

	#[test]
	fn test_h3_settings_frame_not_tuic_version() {
		let frame = build_h3_settings_frame();
		// First byte must NOT be TUIC version (0x05)
		assert_ne!(frame[0], 0x05, "first byte must not be TUIC version byte");
	}

	#[test]
	fn test_h3_settings_frame_has_valid_length() {
		let frame = build_h3_settings_frame();
		// Should have: control_type(1) + frame_type(1) + length(1) + settings_payload
		assert!(
			frame.len() >= 4,
			"frame must have at least control type + frame type + length + payload"
		);

		// Verify declared length matches actual payload
		let declared_len = frame[2] as usize;
		let actual_payload = frame.len() - 3; // skip control_type + frame_type + length byte
		assert_eq!(
			declared_len, actual_payload,
			"declared frame length must match actual payload size"
		);
	}

	#[test]
	fn test_h3_settings_frame_contains_known_settings() {
		let frame = build_h3_settings_frame();
		// Should contain QPACK_MAX_TABLE_CAPACITY setting id (0x01)
		assert!(frame.contains(&0x01), "should contain QPACK_MAX_TABLE_CAPACITY setting");
		// Should contain QPACK_BLOCKED_STREAMS setting id (0x07)
		assert!(frame.contains(&0x07), "should contain QPACK_BLOCKED_STREAMS setting");
		// Should contain MAX_FIELD_SECTION_SIZE setting id (0x06)
		assert!(frame.contains(&0x06), "should contain MAX_FIELD_SECTION_SIZE setting");
	}

	#[test]
	fn test_h3_goaway_frame_structure() {
		let frame = build_h3_goaway_frame();
		assert_eq!(frame[0], H3_FRAME_TYPE_GOAWAY, "first byte must be GOAWAY frame type");
		assert_eq!(frame[1], 0x01, "length should be 1");
		assert_eq!(frame[2], 0x00, "stream id should be 0");
	}
}
