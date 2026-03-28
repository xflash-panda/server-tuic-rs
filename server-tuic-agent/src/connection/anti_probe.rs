use rand::{Rng, prelude::IndexedRandom};
use tracing::debug;
/// Encode a u64 value as a QUIC variable-length integer (RFC 9000 Section 16).
fn encode_varint(buf: &mut Vec<u8>, value: u64) {
	if value <= 63 {
		buf.push(value as u8);
	} else if value <= 16383 {
		buf.push(((value >> 8) as u8) | 0x40);
		buf.push(value as u8);
	} else if value <= 1_073_741_823 {
		let bytes = (value as u32).to_be_bytes();
		buf.push(bytes[0] | 0x80);
		buf.extend_from_slice(&bytes[1..]);
	} else {
		let bytes = value.to_be_bytes();
		buf.push(bytes[0] | 0xc0);
		buf.extend_from_slice(&bytes[1..]);
	}
}

/// Build an H3 control stream: stream type 0x00 + SETTINGS frame with
/// randomized values.
fn build_h3_control_stream() -> Vec<u8> {
	let mut rng = rand::rng();

	// Randomize setting values
	let capacity_choices = [0u64, 4096, 16384, 65536];
	let capacity = *capacity_choices.choose(&mut rng).unwrap();

	let field_section_size = rng.random_range(8192u64..=65536);

	let blocked_streams_choices = [0u64, 10, 16, 100, 128];
	let blocked_streams = *blocked_streams_choices.choose(&mut rng).unwrap();

	// Build settings payload: pairs of (setting_id, value) as varints
	let mut settings_payload = Vec::new();
	// QPACK_MAX_TABLE_CAPACITY (0x01)
	encode_varint(&mut settings_payload, 0x01);
	encode_varint(&mut settings_payload, capacity);
	// MAX_FIELD_SECTION_SIZE (0x06)
	encode_varint(&mut settings_payload, 0x06);
	encode_varint(&mut settings_payload, field_section_size);
	// QPACK_BLOCKED_STREAMS (0x07)
	encode_varint(&mut settings_payload, 0x07);
	encode_varint(&mut settings_payload, blocked_streams);

	let mut buf = Vec::new();
	// Stream type: control (0x00)
	buf.push(0x00);
	// SETTINGS frame type (0x04)
	encode_varint(&mut buf, 0x04);
	// SETTINGS frame length
	encode_varint(&mut buf, settings_payload.len() as u64);
	buf.extend_from_slice(&settings_payload);

	buf
}

/// Build an H3 QPACK encoder stream (stream type 0x02).
fn build_qpack_encoder_stream() -> Vec<u8> {
	vec![0x02]
}

/// Build an H3 QPACK decoder stream (stream type 0x03).
fn build_qpack_decoder_stream() -> Vec<u8> {
	vec![0x03]
}

/// Build a QPACK-encoded header block for a 404 response.
///
/// Uses static-only encoding (no dynamic table):
/// - Required Insert Count = 0
/// - Delta Base = 0
/// - :status 404 (static index 29)
/// - content-type: text/html (literal with static name ref)
/// - server: nginx (literal with static name ref)
fn build_qpack_404_header_block() -> Vec<u8> {
	#[rustfmt::skip]
	let mut buf = vec![
		// QPACK prefix: Required Insert Count = 0, Delta Base = 0
		0x00, 0x00,
		// Indexed field line (static): :status 404, index 29
		// Pattern: 1_1_xxxxxx (T=1 static, 6-bit prefix), 11_011101 = 0xDD
		0xDD,
		// Literal header with name reference (static): content-type: text/html
		// Pattern: 0101_xxxx (N=0, T=1), static index 44 (overflow: 0x5F, 44-15=0x1D)
		0x5F, 0x1D,
		// Value: "text/html" (9 bytes, no Huffman H=0)
		0x09,
	];
	buf.extend_from_slice(b"text/html");
	// Literal header with name reference (static): server: nginx
	// static index 92 (overflow: 0x5F, 92-15=0x4D)
	buf.extend_from_slice(&[0x5F, 0x4D, 0x05]);
	buf.extend_from_slice(b"nginx");
	buf
}

/// Build an H3 HEADERS frame (type 0x01) wrapping a QPACK-encoded header block.
fn build_h3_headers_frame(header_block: &[u8]) -> Vec<u8> {
	let mut buf = Vec::new();
	encode_varint(&mut buf, 0x01); // HEADERS frame type
	encode_varint(&mut buf, header_block.len() as u64);
	buf.extend_from_slice(header_block);
	buf
}

/// Build an H3 DATA frame (type 0x00) wrapping a body.
fn build_h3_data_frame(body: &[u8]) -> Vec<u8> {
	let mut buf = Vec::new();
	encode_varint(&mut buf, 0x00); // DATA frame type
	encode_varint(&mut buf, body.len() as u64);
	buf.extend_from_slice(body);
	buf
}

/// Build a complete H3 404 response (HEADERS + DATA frames).
fn build_h3_404_response() -> Vec<u8> {
	let body = b"<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>";
	let header_block = build_qpack_404_header_block();
	let mut response = build_h3_headers_frame(&header_block);
	response.extend_from_slice(&build_h3_data_frame(body));
	response
}

/// Send an H3 404 response on the bidirectional stream that triggered the
/// probe.
pub async fn send_h3_bidi_response(send: &mut quinn::SendStream) {
	let response = build_h3_404_response();
	if let Err(e) = send.write_all(&response).await {
		debug!("anti-probe: failed to write H3 bidi response: {e}");
		return;
	}
	if let Err(e) = send.finish() {
		debug!("anti-probe: failed to finish H3 bidi stream: {e}");
	}
}

/// Send an H3 probe response by opening control + QPACK uni streams.
pub async fn send_h3_probe_response(conn: &quinn::Connection) {
	let control = build_h3_control_stream();
	let encoder = build_qpack_encoder_stream();
	let decoder = build_qpack_decoder_stream();

	let send_stream = |data: Vec<u8>, name: &'static str| {
		let conn = conn.clone();
		async move {
			match conn.open_uni().await {
				Ok(mut stream) => {
					if let Err(e) = stream.write_all(&data).await {
						debug!("anti-probe: failed to write {name} stream: {e}");
					}
					// Don't finish the stream — real H3 servers keep them open
				}
				Err(e) => {
					debug!("anti-probe: failed to open {name} uni stream: {e}");
				}
			}
		}
	};

	tokio::join!(
		send_stream(control, "control"),
		send_stream(encoder, "qpack-encoder"),
		send_stream(decoder, "qpack-decoder"),
	);
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_qpack_encoder_stream_bytes() {
		assert_eq!(build_qpack_encoder_stream(), vec![0x02]);
	}

	#[test]
	fn test_qpack_decoder_stream_bytes() {
		assert_eq!(build_qpack_decoder_stream(), vec![0x03]);
	}

	#[test]
	fn test_h3_control_stream_starts_with_type() {
		let bytes = build_h3_control_stream();
		assert_eq!(bytes[0], 0x00, "first byte should be control stream type");
		assert_eq!(bytes[1], 0x04, "second byte should be SETTINGS frame type");
	}

	#[test]
	fn test_h3_control_stream_contains_settings() {
		let bytes = build_h3_control_stream();
		assert!(bytes.len() >= 4, "control stream should have at least 4 bytes");
	}

	#[test]
	fn test_settings_values_randomized() {
		let results: Vec<Vec<u8>> = (0..10).map(|_| build_h3_control_stream()).collect();
		let all_identical = results.windows(2).all(|w| w[0] == w[1]);
		assert!(
			!all_identical,
			"10 calls to build_h3_control_stream should not all produce identical output"
		);
	}

	fn is_tuic_protocol(first_byte: u8) -> bool {
		first_byte == tuic::VERSION
	}

	#[test]
	fn test_is_tuic_version() {
		assert!(is_tuic_protocol(0x05));
		assert!(!is_tuic_protocol(0x00));
		assert!(!is_tuic_protocol(0x04));
		assert!(!is_tuic_protocol(0xFF));
	}

	#[test]
	fn test_encode_varint_1byte() {
		let mut buf = Vec::new();
		encode_varint(&mut buf, 37);
		assert_eq!(buf, vec![37]);
	}

	#[test]
	fn test_encode_varint_2byte() {
		let mut buf = Vec::new();
		encode_varint(&mut buf, 15293);
		assert_eq!(buf, vec![0x7b, 0xbd]);
	}

	#[test]
	fn test_encode_varint_zero() {
		let mut buf = Vec::new();
		encode_varint(&mut buf, 0);
		assert_eq!(buf, vec![0x00]);
	}

	#[test]
	fn test_encode_varint_max_1byte() {
		let mut buf = Vec::new();
		encode_varint(&mut buf, 63);
		assert_eq!(buf, vec![63]);
	}

	#[test]
	fn test_encode_varint_min_2byte() {
		let mut buf = Vec::new();
		encode_varint(&mut buf, 64);
		assert_eq!(buf, vec![0x40, 0x40]);
	}

	#[test]
	fn test_h3_control_stream_valid_structure() {
		let bytes = build_h3_control_stream();
		assert!(
			bytes.len() >= 9,
			"control stream with 3 settings should be at least 9 bytes, got {}",
			bytes.len()
		);
	}

	// --- H3 bidi response tests (RED phase) ---

	#[test]
	fn test_build_qpack_404_header_block() {
		let block = build_qpack_404_header_block();
		// QPACK encoded header block for :status 404:
		// - Required Insert Count = 0 (8-bit prefix varint): 0x00
		// - S=0, Delta Base = 0 (7-bit prefix varint): 0x00
		// - Indexed field line, static, index 29 (:status 404): 0xDD
		assert_eq!(&block[..2], &[0x00, 0x00], "QPACK prefix should be 0x00 0x00");
		// Third byte: indexed static field line for :status 404
		assert_eq!(block[2], 0xDD, "should encode :status 404 as indexed static field line");
		// Should have more bytes for additional headers (content-type, server, etc.)
		assert!(block.len() > 3, "should include additional response headers beyond :status");
		// Verify content-type literal with name ref (static index 44)
		// 0x5F = 0101_1111 (literal, N=0, T=1, overflow), 0x1D = 44-15 = 29
		assert_eq!(block[3], 0x5F, "content-type should start with literal name ref prefix");
		assert_eq!(block[4], 0x1D, "content-type name index should be 44 (overflow: 29)");
		// Value length + "text/html"
		assert_eq!(block[5], 0x09, "content-type value length should be 9");
		assert_eq!(&block[6..15], b"text/html", "content-type value should be text/html");
	}

	#[test]
	fn test_build_h3_headers_frame() {
		let header_block = vec![0x00, 0x00, 0xDD]; // minimal QPACK block
		let frame = build_h3_headers_frame(&header_block);
		// H3 HEADERS frame: type=0x01, length=3, payload
		assert_eq!(frame[0], 0x01, "frame type should be HEADERS (0x01)");
		assert_eq!(frame[1], 0x03, "frame length should be 3");
		assert_eq!(&frame[2..], &[0x00, 0x00, 0xDD], "payload should match header block");
	}

	#[test]
	fn test_build_h3_data_frame() {
		let body = b"<html><body>404</body></html>";
		let frame = build_h3_data_frame(body);
		// H3 DATA frame: type=0x00, length=varint(body.len()), payload=body
		assert_eq!(frame[0], 0x00, "frame type should be DATA (0x00)");
		// body is 29 bytes, fits in 1-byte varint
		assert_eq!(frame[1], body.len() as u8, "frame length should be body length");
		assert_eq!(&frame[2..], body, "payload should match body");
	}

	#[test]
	fn test_build_h3_data_frame_empty_body() {
		let frame = build_h3_data_frame(b"");
		assert_eq!(frame[0], 0x00, "frame type should be DATA (0x00)");
		assert_eq!(frame[1], 0x00, "frame length should be 0");
		assert_eq!(frame.len(), 2, "empty body frame should be 2 bytes");
	}

	#[test]
	fn test_build_h3_404_response() {
		let response = build_h3_404_response();
		// Should start with HEADERS frame (type 0x01)
		assert_eq!(response[0], 0x01, "response should start with HEADERS frame type");
		// After HEADERS frame, should contain DATA frame (type 0x00)
		// Find DATA frame by skipping past HEADERS frame
		let headers_len = response[1] as usize; // length byte
		let data_frame_start = 2 + headers_len;
		assert!(
			data_frame_start < response.len(),
			"response should contain DATA frame after HEADERS"
		);
		assert_eq!(
			response[data_frame_start], 0x00,
			"DATA frame type should follow HEADERS frame"
		);
	}

	#[test]
	fn test_build_h3_404_response_has_html_body() {
		let response = build_h3_404_response();
		// The response body should contain HTML
		let response_str = String::from_utf8_lossy(&response);
		assert!(
			response_str.contains("<html") || response_str.contains("404"),
			"response should contain HTML body with 404"
		);
	}
}
