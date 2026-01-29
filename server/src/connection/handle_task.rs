use std::{
	collections::hash_map::Entry,
	io::{Error as IoError, ErrorKind},
	net::{IpAddr, SocketAddr},
};

use bytes::Bytes;
use eyre::eyre;
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt},
	net::{self, TcpSocket, TcpStream},
};
use tracing::debug;
use tuic::{
	Address, is_private_ip,
	quinn::{Authenticate, Connect, Packet},
};

use super::{Connection, ERROR_CODE, UdpSession};
use crate::{
	acl::{IpMode, OutboundHandler, Protocol},
	io::copy_io,
	stats,
	utils::UdpRelayMode,
};

impl Connection {
	fn should_drop_address(&self, addrs: &[SocketAddr]) -> bool {
		// Built-in safety: drop localhost/private if configured
		if self.ctx.cfg.experimental.drop_loopback && addrs.iter().any(|sa| sa.ip().is_loopback()) {
			return true;
		}
		if self.ctx.cfg.experimental.drop_private && addrs.iter().any(|sa| is_private_ip(&sa.ip())) {
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
			let outbound = if let Some(acl_engine) = &self.ctx.cfg.acl_engine {
				// Extract host and port from address
				let (host, port) = match conn.addr() {
					Address::DomainAddress(domain, port) => (domain.as_str(), *port),
					Address::SocketAddress(addr) => {
						// Convert IP to string for matching
						let ip_str = addr.ip().to_string();
						// Leak string to get &'static str (acceptable for IP addresses)
						(Box::leak(ip_str.into_boxed_str()) as &str, addr.port())
					}
					Address::None => ("", 0),
				};

				// Match using ACL engine (no HostInfo struct needed)
				match acl_engine.match_host(host, port, Protocol::TCP) {
					Some(handler) => handler,
					None => {
						// No match, use default direct
						std::sync::Arc::new(OutboundHandler::Direct { mode: IpMode::Auto })
					}
				}
			} else {
				// No ACL engine (shouldn't happen after config changes), use default direct
				std::sync::Arc::new(OutboundHandler::Direct { mode: IpMode::Auto })
			};

			// Handle outbound based on type
			match outbound.as_ref() {
				OutboundHandler::Reject => {
					debug!(
						"[{id:#010x}] [{addr}] [{user}] [TCP] {target_addr} rejected by ACL",
						id = self.id(),
						addr = self.inner.remote_address(),
						user = self.auth,
					);
					_ = conn.reset(ERROR_CODE);
					return Ok(());
				}
				OutboundHandler::Direct { mode } => {
					// Resolve and filter addresses based on IP mode
					let initial_addrs = self.resolve_and_filter_addresses_new(conn.addr(), *mode).await?;

					// Check if address should be blocked (experimental filters)
					if self.should_drop_address(&initial_addrs) {
						debug!(
							"[{id:#010x}] [{addr}] [{user}] [TCP] {target_addr} blocked (loopback/private)",
							id = self.id(),
							addr = self.inner.remote_address(),
							user = self.auth,
						);
						_ = conn.reset(ERROR_CODE);
						return Ok(());
					}

					// Connect directly
					let mut stream = self.connect_to_addresses_new(initial_addrs, *mode).await?;
					stream.set_nodelay(true)?;

					// Copy data bidirectionally
					let (tx, rx, err) = copy_io(&mut conn, &mut stream).await;
					if err.is_some() {
						_ = conn.reset(ERROR_CODE);
					} else {
						_ = conn.finish();
					}
					_ = stream.shutdown().await;

					// Record traffic stats
					if self.auth.is_authenticated() {
						let uid = self.auth.get_uid();
						stats::req_incr(&self.ctx, uid).await;
						stats::traffic_tx(&self.ctx, uid, tx).await;
						stats::traffic_rx(&self.ctx, uid, rx).await;
					}

					if let Some(err) = err {
						return Err(err.into());
					}
				}
				OutboundHandler::Socks5 { config } => {
					// Connect via SOCKS5
					let mut stream = self.connect_via_socks5_new(config, conn.addr()).await?;
					stream.set_nodelay(true)?;

					// Copy data bidirectionally
					let (tx, rx, err) = copy_io(&mut conn, &mut stream).await;
					if err.is_some() {
						_ = conn.reset(ERROR_CODE);
					} else {
						_ = conn.finish();
					}
					_ = stream.shutdown().await;

					// Record traffic stats
					if self.auth.is_authenticated() {
						let uid = self.auth.get_uid();
						stats::req_incr(&self.ctx, uid).await;
						stats::traffic_tx(&self.ctx, uid, tx).await;
						stats::traffic_rx(&self.ctx, uid, rx).await;
					}

					if let Some(err) = err {
						return Err(err.into());
					}
				}
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

	// ACL-based methods
	async fn resolve_and_filter_addresses_new(&self, addr: &Address, mode: IpMode) -> eyre::Result<Vec<SocketAddr>> {
		let mut addrs: Vec<SocketAddr> = resolve_dns(addr).await?.collect();

		match mode {
			IpMode::Auto => {
				// Prefer IPv4 first by default
				addrs.sort_by_key(|a| !a.is_ipv4());
			}
			IpMode::V4Only => {
				addrs.retain(|a| a.is_ipv4());
			}
			IpMode::V6Only => {
				addrs.retain(|a| a.is_ipv6());
			}
		}

		if addrs.is_empty() {
			return Err(eyre!("No addresses available after IP mode filtering"));
		}

		Ok(addrs)
	}

	async fn connect_to_addresses_new(&self, addrs: Vec<SocketAddr>, _mode: IpMode) -> eyre::Result<TcpStream> {
		let mut last_error: Option<eyre::Report> = None;

		for addr in addrs {
			match self.create_socket_simple(&addr) {
				Ok(socket) => match socket.connect(addr).await {
					Ok(stream) => return Ok(stream),
					Err(err) => last_error = Some(err.into()),
				},
				Err(err) => last_error = Some(err),
			}
		}

		Err(last_error.unwrap_or_else(|| eyre!("Failed to connect to any address")))
	}

	fn create_socket_simple(&self, addr: &SocketAddr) -> eyre::Result<TcpSocket> {
		let socket = if addr.is_ipv4() {
			TcpSocket::new_v4()?
		} else {
			TcpSocket::new_v6()?
		};

		Ok(socket)
	}

	async fn connect_via_socks5_new(&self, config: &crate::acl::Socks5Config, addr: &Address) -> eyre::Result<TcpStream> {
		// Parse SOCKS5 server address
		let socks5_addr = match config.addr.parse::<SocketAddr>() {
			Ok(addr) => addr,
			Err(_) => {
				// Try to resolve if it's a hostname
				let parts: Vec<&str> = config.addr.splitn(2, ':').collect();
				if parts.len() == 2 {
					let host = parts[0];
					let port: u16 = parts[1].parse().map_err(|_| eyre!("Invalid port in SOCKS5 address"))?;
					let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:{}", host, port)).await?.collect();
					addrs
						.into_iter()
						.next()
						.ok_or_else(|| eyre!("No address resolved for SOCKS5 server"))?
				} else {
					return Err(eyre!("Invalid SOCKS5 address format"));
				}
			}
		};

		// Connect to SOCKS5 server
		let mut stream = TcpStream::connect(socks5_addr).await?;

		// SOCKS5 handshake
		// Send greeting
		if config.username.is_some() && config.password.is_some() {
			// Username/password authentication
			stream.write_all(&[0x05, 0x01, 0x02]).await?; // VER, NMETHODS, METHOD (username/password)
		} else {
			// No authentication
			stream.write_all(&[0x05, 0x01, 0x00]).await?; // VER, NMETHODS, METHOD (no auth)
		}

		// Read method selection
		let mut buf = [0u8; 2];
		stream.read_exact(&mut buf).await?;
		if buf[0] != 0x05 {
			return Err(eyre!("Invalid SOCKS5 version response"));
		}

		// Handle authentication if required
		if buf[1] == 0x02 {
			// Username/password authentication
			let username = config.username.as_ref().ok_or_else(|| eyre!("Username required"))?;
			let password = config.password.as_ref().ok_or_else(|| eyre!("Password required"))?;

			let mut auth_req = vec![0x01]; // VER
			auth_req.push(username.len() as u8);
			auth_req.extend_from_slice(username.as_bytes());
			auth_req.push(password.len() as u8);
			auth_req.extend_from_slice(password.as_bytes());
			stream.write_all(&auth_req).await?;

			// Read auth response
			let mut auth_resp = [0u8; 2];
			stream.read_exact(&mut auth_resp).await?;
			if auth_resp[1] != 0x00 {
				return Err(eyre!("SOCKS5 authentication failed"));
			}
		} else if buf[1] != 0x00 {
			return Err(eyre!("SOCKS5 server requires unsupported authentication"));
		}

		// Send connect request
		let mut req = vec![0x05, 0x01, 0x00]; // VER, CMD (CONNECT), RSV

		match addr {
			Address::DomainAddress(domain, port) => {
				req.push(0x03); // ATYP (domain)
				req.push(domain.len() as u8);
				req.extend_from_slice(domain.as_bytes());
				req.extend_from_slice(&port.to_be_bytes());
			}
			Address::SocketAddress(sock_addr) => {
				match sock_addr.ip() {
					IpAddr::V4(ipv4) => {
						req.push(0x01); // ATYP (IPv4)
						req.extend_from_slice(&ipv4.octets());
					}
					IpAddr::V6(ipv6) => {
						req.push(0x04); // ATYP (IPv6)
						req.extend_from_slice(&ipv6.octets());
					}
				}
				req.extend_from_slice(&sock_addr.port().to_be_bytes());
			}
			Address::None => {
				return Err(eyre!("Cannot connect to None address"));
			}
		}

		stream.write_all(&req).await?;

		// Read connect response
		let mut resp = [0u8; 4];
		stream.read_exact(&mut resp).await?;
		if resp[0] != 0x05 {
			return Err(eyre!("Invalid SOCKS5 version in connect response"));
		}
		if resp[1] != 0x00 {
			return Err(eyre!("SOCKS5 connect failed with code: {}", resp[1]));
		}

		// Read bound address (we don't use it, but must consume it)
		match resp[3] {
			0x01 => {
				// IPv4
				let mut addr_buf = [0u8; 6]; // 4 bytes IP + 2 bytes port
				stream.read_exact(&mut addr_buf).await?;
			}
			0x03 => {
				// Domain
				let mut len_buf = [0u8; 1];
				stream.read_exact(&mut len_buf).await?;
				let mut domain_buf = vec![0u8; len_buf[0] as usize + 2]; // domain + 2 bytes port
				stream.read_exact(&mut domain_buf).await?;
			}
			0x04 => {
				// IPv6
				let mut addr_buf = [0u8; 18]; // 16 bytes IP + 2 bytes port
				stream.read_exact(&mut addr_buf).await?;
			}
			_ => return Err(eyre!("Invalid address type in SOCKS5 response")),
		}

		Ok(stream)
	}

	// Legacy methods (kept for backward compatibility, can be removed later)
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
			let outbound = if let Some(acl_engine) = &self.ctx.cfg.acl_engine {
				// Extract host and port from address
				let (host, port) = match &addr {
					Address::DomainAddress(domain, port) => (domain.as_str(), *port),
					Address::SocketAddress(addr) => {
						let ip_str = addr.ip().to_string();
						(Box::leak(ip_str.into_boxed_str()) as &str, addr.port())
					}
					Address::None => ("", 0),
				};

				// Match using ACL engine for UDP
				match acl_engine.match_host(host, port, Protocol::UDP) {
					Some(handler) => handler,
					None => {
						// No match, use default direct
						std::sync::Arc::new(OutboundHandler::Direct { mode: IpMode::Auto })
					}
				}
			} else {
				// No ACL engine, use default direct
				std::sync::Arc::new(OutboundHandler::Direct { mode: IpMode::Auto })
			};

			// Handle outbound based on type
			let socket_addr = match outbound.as_ref() {
				OutboundHandler::Reject => {
					debug!(
						"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to \
						 {src_addr} rejected by ACL",
						id = self.id(),
						addr = self.inner.remote_address(),
						user = self.auth,
						src_addr = addr,
					);
					return Ok(());
				}
				OutboundHandler::Direct { mode: ip_mode } => {
					// Resolve and filter addresses
					let initial_addrs = self.resolve_and_filter_addresses_new(&addr, *ip_mode).await?;

					// Check if address should be blocked (experimental filters)
					if self.should_drop_address(&initial_addrs) {
						debug!(
							"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to \
							 {src_addr} blocked (loopback/private)",
							id = self.id(),
							addr = self.inner.remote_address(),
							user = self.auth,
							src_addr = addr,
						);
						return Ok(());
					}

					// Use the first resolved address
					initial_addrs[0]
				}
				OutboundHandler::Socks5 { config } => {
					// Check if UDP is allowed
					if !config.allow_udp {
						debug!(
							"[{id:#010x}] [{addr}] [{user}] [UDP-OUT-SOCKS5] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] \
							 to {src_addr} blocked (UDP not allowed for SOCKS5)",
							id = self.id(),
							addr = self.inner.remote_address(),
							user = self.auth,
							src_addr = addr,
						);
						// Silently drop UDP to avoid leaking QUIC/HTTP3
						return Ok(());
					} else {
						// UDP via SOCKS5 not supported yet; fall back to direct
						debug!(
							"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] UDP via SOCKS5 not supported; using \
							 direct",
							id = self.id(),
							addr = self.inner.remote_address(),
							user = self.auth,
						);

						// Resolve with auto mode
						let initial_addrs = self.resolve_and_filter_addresses_new(&addr, IpMode::Auto).await?;

						// Check if address should be blocked
						if self.should_drop_address(&initial_addrs) {
							debug!(
								"[{id:#010x}] [{addr}] [{user}] [UDP-OUT] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] to \
								 {src_addr} blocked (loopback/private)",
								id = self.id(),
								addr = self.inner.remote_address(),
								user = self.auth,
								src_addr = addr,
							);
							return Ok(());
						}

						initial_addrs[0]
					}
				}
			};

			// Record traffic and request stats for UDP outbound
			if self.auth.is_authenticated() {
				let uid = self.auth.get_uid();
				stats::req_incr(&self.ctx, uid).await;
				stats::traffic_tx(&self.ctx, uid, pkt.len()).await;
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
			stats::traffic_rx(&self.ctx, self.auth.get_uid(), pkt.len()).await;
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

async fn resolve_dns(addr: &Address) -> Result<impl Iterator<Item = SocketAddr>, IoError> {
	match addr {
		Address::None => Err(IoError::new(ErrorKind::InvalidInput, "empty address")),
		Address::DomainAddress(domain, port) => Ok(net::lookup_host((domain.as_str(), *port))
			.await?
			.collect::<Vec<_>>()
			.into_iter()),
		Address::SocketAddress(addr) => Ok(vec![*addr].into_iter()),
	}
}

impl Connection {}
