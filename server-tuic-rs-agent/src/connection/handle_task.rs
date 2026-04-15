use std::{collections::hash_map::Entry, net::SocketAddr};

use bytes::Bytes;
use eyre::eyre;
use tokio::io::AsyncWriteExt;
use tracing::debug;
use tuic::{
	Address, is_private_ip,
	quinn::{Authenticate, Connect, Packet},
};

use super::{Connection, ERROR_CODE, UdpSession};
use crate::{
	acl::{Addr, OutboundHandler, Protocol},
	io::copy_io,
	stats,
	utils::UdpRelayMode,
};

impl Connection {
	fn should_drop_address(&self, addr: &SocketAddr) -> bool {
		// Built-in safety: drop localhost/private if configured
		if self.ctx.cfg.experimental.drop_loopback && addr.ip().is_loopback() {
			return true;
		}
		if self.ctx.cfg.experimental.drop_private && is_private_ip(&addr.ip()) {
			return true;
		}
		false
	}

	pub async fn handle_authenticate(&self, auth: Authenticate) {
		debug!(
			"[{id:#010x}] [{addr}] [{user}] [AUTH] {auth_uuid}",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
			auth_uuid = auth.uuid(),
		);
	}

	pub async fn handle_connect(&self, mut conn: Connect) {
		let target_addr = conn.addr().to_string();

		debug!(
			"[{id:#010x}] [{addr}] [{user}] [TCP] {target_addr} ",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
		);

		let process = async {
			// Match against ACL engine
			let outbound = self.get_outbound_handler(conn.addr(), Protocol::TCP);

			// Handle reject early
			if outbound.is_reject() {
				debug!(
					"[{id:#010x}] [{addr}] [{user}] [TCP] {target_addr} rejected by ACL",
					id = self.id(),
					addr = self.inner.remote_address(),
					user = self.auth,
				);
				_ = conn.reset(ERROR_CODE);
				return Ok(());
			}

			// Convert Address to acl-engine-rs Addr
			let mut acl_addr = address_to_acl_addr(conn.addr());

			// Use acl-engine-rs's async outbound to dial TCP
			let tcp_conn = outbound
				.as_async_outbound()
				.dial_tcp(&mut acl_addr)
				.await
				.map_err(|e| eyre!("Failed to connect: {}", e))?;

			// Check if the peer address should be blocked (experimental filters)
			// Only check for Direct outbound - for proxied connections (Socks5, etc.),
			// peer_addr() returns the proxy server address, not the actual target
			if matches!(outbound.as_ref(), OutboundHandler::Direct(_)) {
				if let Ok(peer_addr) = tcp_conn.peer_addr() {
					if self.should_drop_address(&peer_addr) {
						debug!(
							"[{id:#010x}] [{addr}] [{user}] [TCP] {target_addr} blocked (loopback/private)",
							id = self.id(),
							addr = self.inner.remote_address(),
							user = self.auth,
						);
						_ = conn.reset(ERROR_CODE);
						return Ok(());
					}
				}
			}

			// Convert to tokio-compatible stream for copy_io
			let mut stream = tcp_conn;

			// Copy data bidirectionally
			let (tx, rx, err) = copy_io(&mut conn, &mut stream).await;
			if err.is_some() {
				_ = conn.reset(ERROR_CODE);
			} else {
				_ = conn.finish().await;
			}
			_ = stream.shutdown().await;

			// Record traffic stats
			if self.auth.is_authenticated() {
				let uid = self.auth.get_uid();
				stats::req_incr(&self.ctx, uid);
				stats::traffic_tx(&self.ctx, uid, tx);
				stats::traffic_rx(&self.ctx, uid, rx);
			}

			if let Some(err) = err {
				return Err(err.into());
			}

			eyre::Ok(())
		};

		match process.await {
			Ok(()) => {}
			Err(err) => debug!(
				"[{id:#010x}] [{addr}] [{user}] [TCP] {target_addr}: {err}",
				id = self.id(),
				addr = self.inner.remote_address(),
				user = self.auth,
			),
		}
	}

	/// Get outbound handler for the given address and protocol
	fn get_outbound_handler(&self, addr: &Address, protocol: Protocol) -> std::sync::Arc<OutboundHandler> {
		if let Some(acl_engine) = &self.ctx.cfg.acl_engine {
			// Extract host and port from address
			let (host_owned, port) = match addr {
				Address::DomainAddress(domain, port) => (domain.clone(), *port),
				Address::SocketAddress(addr) => (addr.ip().to_string(), addr.port()),
				Address::None => (String::new(), 0),
			};

			// Match using ACL engine
			match acl_engine.match_host(&host_owned, port, protocol) {
				Some(handler) => handler,
				None => {
					// No match, use default direct
					std::sync::Arc::new(OutboundHandler::Direct(std::sync::Arc::new(
						acl_engine_rs::outbound::Direct::new(),
					)))
				}
			}
		} else {
			// No ACL engine, use default direct
			std::sync::Arc::new(OutboundHandler::Direct(std::sync::Arc::new(
				acl_engine_rs::outbound::Direct::new(),
			)))
		}
	}

	pub async fn handle_packet(&self, pkt: Packet, mode: UdpRelayMode) {
		let assoc_id = pkt.assoc_id();
		let pkt_id = pkt.pkt_id();
		let frag_id = pkt.frag_id();
		let frag_total = pkt.frag_total();

		debug!(
			"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] fragment \
			 {frag_id}/{frag_total}",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
			frag_id = frag_id + 1,
		);

		self.udp_relay_mode.store(Some(mode).into());

		let (pkt, addr, assoc_id) = match pkt.accept().await {
			Ok(None) => return,
			Ok(Some(res)) => res,
			Err(err) => {
				debug!(
					"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] fragment \
					 {frag_id}/{frag_total}: {err}",
					id = self.id(),
					addr = self.inner.remote_address(),
					user = self.auth,
					frag_id = frag_id + 1,
				);
				return;
			}
		};

		let process = async {
			debug!(
				"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to {src_addr}",
				id = self.id(),
				addr = self.inner.remote_address(),
				user = self.auth,
				src_addr = addr,
			);

			let guard = self.udp_sessions.read().await;
			let session = guard.get(&assoc_id).map(|v| v.to_owned());
			drop(guard);
			let session = match session {
				Some(v) => v,
				None => match self.udp_sessions.write().await.entry(assoc_id) {
					Entry::Occupied(entry) => entry.get().clone(),
					Entry::Vacant(entry) => {
						let session = UdpSession::new(self.ctx.clone(), self.clone(), assoc_id)?;
						entry.insert(session.clone());
						session
					}
				},
			};

			// Match against ACL engine for UDP
			let outbound = self.get_outbound_handler(&addr, Protocol::UDP);

			// Handle reject
			if outbound.is_reject() {
				debug!(
					"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to {src_addr} \
					 rejected by ACL",
					id = self.id(),
					addr = self.inner.remote_address(),
					user = self.auth,
					src_addr = addr,
				);
				return Ok(());
			}

			// Check UDP support
			if !outbound.allows_udp() {
				debug!(
					"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to {src_addr} \
					 blocked (UDP not allowed for this outbound)",
					id = self.id(),
					addr = self.inner.remote_address(),
					user = self.auth,
					src_addr = addr,
				);
				return Ok(());
			}

			// Use acl-engine-rs's async outbound to get UDP connection
			let mut acl_addr = address_to_acl_addr(&addr);
			let udp_conn = outbound
				.as_async_outbound()
				.dial_udp(&mut acl_addr)
				.await
				.map_err(|e| eyre!("Failed to create UDP connection: {}", e))?;

			// Get the resolved address for sending
			let socket_addr = acl_addr
				.resolve_info()
				.as_ref()
				.and_then(|info| {
					info.ipv4
						.map(|ipv4| SocketAddr::new(std::net::IpAddr::V4(ipv4), acl_addr.port()))
						.or_else(|| {
							info.ipv6
								.map(|ipv6| SocketAddr::new(std::net::IpAddr::V6(ipv6), acl_addr.port()))
						})
				})
				.or_else(|| {
					// Try to parse the host as a socket address
					format!("{}:{}", acl_addr.host(), acl_addr.port()).parse().ok()
				})
				.ok_or_else(|| eyre!("Failed to resolve UDP target address"))?;

			// Check if address should be blocked (experimental filters)
			// Only check for Direct outbound - for proxied connections, the target
			// is handled by the proxy and we shouldn't block based on resolved address
			if matches!(outbound.as_ref(), OutboundHandler::Direct(_)) && self.should_drop_address(&socket_addr) {
				debug!(
					"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to {src_addr} \
					 blocked (loopback/private)",
					id = self.id(),
					addr = self.inner.remote_address(),
					user = self.auth,
					src_addr = addr,
				);
				return Ok(());
			}

			// Drop the UDP connection from acl-engine-rs (we use our own UdpSession)
			drop(udp_conn);

			// Record traffic and request stats for UDP outbound
			if self.auth.is_authenticated() {
				let uid = self.auth.get_uid();
				stats::req_incr(&self.ctx, uid);
				stats::traffic_tx(&self.ctx, uid, pkt.len());
			}

			if let Some(session) = session.upgrade() {
				session.send(pkt, socket_addr).await
			} else {
				Err(eyre!("UdpSession dropped already").into())
			}
		};

		if let Err(err) = process.await {
			debug!(
				"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to {src_addr}: {err}",
				id = self.id(),
				addr = self.inner.remote_address(),
				user = self.auth,
				src_addr = addr,
			);
		}
	}

	pub async fn handle_dissociate(&self, assoc_id: u16) {
		debug!(
			"[{id:#010x}] [{addr}] [{user}] [UDP-DROP] [{assoc_id:#06x}]",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
		);

		if let Some(session) = self.udp_sessions.write().await.remove(&assoc_id)
			&& let Some(session) = session.upgrade()
		{
			session.close().await;
		}
	}

	pub async fn handle_heartbeat(&self) {
		debug!(
			"[{id:#010x}] [{addr}] [{user}] [HB]",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
		);
	}

	pub async fn relay_packet(self, pkt: Bytes, addr: Address, assoc_id: u16) -> eyre::Result<()> {
		let addr_display = addr.to_string();

		debug!(
			"[{id:#010x}] [{addr}] [{user}] [UDP-IN] [{assoc_id:#06x}] [to-{mode}] from {src_addr}",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
			mode = self.udp_relay_mode.load().unwrap(),
			src_addr = addr_display,
		);

		// Record traffic stats for UDP inbound
		if self.auth.is_authenticated() {
			stats::traffic_rx(&self.ctx, self.auth.get_uid(), pkt.len());
		}

		let res = match self.udp_relay_mode.load().unwrap() {
			UdpRelayMode::Native => self.model.packet_native(pkt, addr, assoc_id),
			UdpRelayMode::Quic => self.model.packet_quic(pkt, addr, assoc_id).await,
		};

		if let Err(err) = res {
			debug!(
				"[{id:#010x}] [{addr}] [{user}] [UDP-IN] [{assoc_id:#06x}] [to-{mode}] from {src_addr}: {err}",
				id = self.id(),
				addr = self.inner.remote_address(),
				user = self.auth,
				mode = self.udp_relay_mode.load().unwrap(),
				src_addr = addr_display,
			);
		}
		Ok(())
	}
}

/// Convert tuic Address to acl-engine-rs Addr
fn address_to_acl_addr(addr: &Address) -> Addr {
	match addr {
		Address::DomainAddress(domain, port) => Addr::new(domain.as_str(), *port),
		Address::SocketAddress(sock_addr) => Addr::new(sock_addr.ip().to_string(), sock_addr.port()),
		Address::None => Addr::new("", 0),
	}
}

impl Connection {}
