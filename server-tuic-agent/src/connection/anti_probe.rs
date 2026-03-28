use rand::{Rng, prelude::IndexedRandom};
use tracing::debug;
use tuic::VERSION as TUIC_VERSION;

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

/// Returns true if the first byte indicates TUIC protocol.
pub fn is_tuic_protocol(first_byte: u8) -> bool {
	first_byte == TUIC_VERSION
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
}
