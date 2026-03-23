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
