use std::{io::Error as IoError, net::SocketAddr};

use quinn::ConnectionError;
use rustls::Error as RustlsError;
use thiserror::Error;
use tuic::quinn::Error as ModelError;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum Error {
	#[error(transparent)]
	Io(#[from] IoError),
	#[error(transparent)]
	Rustls(#[from] RustlsError),
	#[error("invalid max idle time")]
	InvalidMaxIdleTime,
	#[error("connection timed out")]
	TimedOut,
	#[error("connection locally closed")]
	LocallyClosed,
	#[error(transparent)]
	Model(#[from] ModelError),
	#[error("duplicated authentication")]
	DuplicatedAuth,
	#[error("authentication failed: {0}")]
	AuthFailed(Uuid),
	#[error("received packet from unexpected source")]
	UnexpectedPacketSource,
	#[error("{0}: {1}")]
	Socket(&'static str, IoError),
	#[error("task negotiation timed out")]
	TaskNegotiationTimeout,
	#[error("failed sending packet to {0}: relaying IPv6 UDP packet is disabled")]
	UdpRelayIpv6Disabled(SocketAddr),
	#[error(transparent)]
	Other(#[from] eyre::Report),
}

impl Error {
	pub fn is_trivial(&self) -> bool {
		matches!(self, Self::TimedOut | Self::LocallyClosed)
	}

	pub fn is_auth_failed(&self) -> bool {
		matches!(self, Self::AuthFailed(_))
	}

	/// Whether this error should be silently dropped (no connection close) when
	/// anti_probe is enabled. Mimics H3 server ignoring unknown stream types.
	pub fn should_silent_drop_for_anti_probe(&self) -> bool {
		matches!(self, Self::AuthFailed(_) | Self::DuplicatedAuth)
	}

	/// Check if an error indicates a non-TUIC protocol probe on a datagram.
	pub fn is_datagram_probe_error(&self) -> bool {
		matches!(
			self,
			Self::Model(tuic::quinn::Error::UnmarshalDatagram(
				tuic::UnmarshalError::InvalidVersion(_),
				_
			))
		)
	}
}

impl From<ConnectionError> for Error {
	fn from(err: ConnectionError) -> Self {
		match err {
			ConnectionError::TimedOut => Self::TimedOut,
			ConnectionError::LocallyClosed => Self::LocallyClosed,
			_ => Self::Io(IoError::from(err)),
		}
	}
}

#[cfg(test)]
mod tests {
	use uuid::Uuid;

	use super::*;

	#[test]
	fn test_is_auth_failed() {
		let err = Error::AuthFailed(Uuid::nil());
		assert!(err.is_auth_failed());
	}

	#[test]
	fn test_is_auth_failed_false_for_other_errors() {
		assert!(!Error::TimedOut.is_auth_failed());
		assert!(!Error::LocallyClosed.is_auth_failed());
		assert!(!Error::DuplicatedAuth.is_auth_failed());
		assert!(!Error::TaskNegotiationTimeout.is_auth_failed());
	}

	#[test]
	fn test_is_trivial() {
		assert!(Error::TimedOut.is_trivial());
		assert!(Error::LocallyClosed.is_trivial());
		assert!(!Error::AuthFailed(Uuid::nil()).is_trivial());
		assert!(!Error::DuplicatedAuth.is_trivial());
	}

	#[test]
	fn test_should_silent_drop_for_anti_probe_auth_failed() {
		let err = Error::AuthFailed(Uuid::nil());
		assert!(
			err.should_silent_drop_for_anti_probe(),
			"AuthFailed should be silently dropped when anti_probe is enabled"
		);
	}

	#[test]
	fn test_should_silent_drop_for_anti_probe_duplicated_auth() {
		assert!(
			Error::DuplicatedAuth.should_silent_drop_for_anti_probe(),
			"DuplicatedAuth should be silently dropped when anti_probe is enabled"
		);
	}

	#[test]
	fn test_should_not_silent_drop_for_other_errors() {
		assert!(!Error::TimedOut.should_silent_drop_for_anti_probe());
		assert!(!Error::LocallyClosed.should_silent_drop_for_anti_probe());
		assert!(!Error::TaskNegotiationTimeout.should_silent_drop_for_anti_probe());
	}

	#[test]
	fn test_is_datagram_probe_error_invalid_version() {
		let model_err = tuic::quinn::Error::UnmarshalDatagram(
			tuic::UnmarshalError::InvalidVersion(0x21),
			bytes::Bytes::from_static(&[0x21, 0xDE, 0xAD]),
		);
		let err = Error::Model(model_err);
		assert!(
			err.is_datagram_probe_error(),
			"InvalidVersion datagram should be detected as probe"
		);
	}

	#[test]
	fn test_is_datagram_probe_error_false_for_other_errors() {
		assert!(!Error::TimedOut.is_datagram_probe_error());
		assert!(!Error::DuplicatedAuth.is_datagram_probe_error());
		assert!(!Error::TaskNegotiationTimeout.is_datagram_probe_error());
	}
}
