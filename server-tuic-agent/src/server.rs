use std::{
	net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket as StdUdpSocket},
	sync::Arc,
};

use eyre::Context;
use quinn::{
	Endpoint, EndpointConfig, IdleTimeout, ServerConfig, TokioRuntime, TransportConfig, VarInt,
	congestion::{Bbr3Config, ControllerFactory, CubicConfig, NewRenoConfig},
	crypto::rustls::QuicServerConfig,
};
use quinn_congestions::bbr::BbrConfig;
use rustls::ServerConfig as RustlsServerConfig;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tracing::{debug, warn};

use crate::{
	AppContext, congestion::SafePacingFactory, connection::Connection, error::Error, tls::CertResolver,
	utils::CongestionController,
};

pub struct Server {
	ep:  Endpoint,
	ctx: Arc<AppContext>,
}

impl Server {
	pub async fn init(ctx: Arc<AppContext>) -> Result<Self, Error> {
		let expected_sni = if ctx.cfg.experimental.anti_probe {
			ctx.cfg.server_name.clone()
		} else {
			None
		};
		let cert_resolver = CertResolver::new(&ctx.cfg.cert_file, &ctx.cfg.key_file, expected_sni).await?;

		let mut crypto = RustlsServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
			.with_no_client_auth()
			.with_cert_resolver(cert_resolver);

		// Set ALPN protocols - required for Clash Meta and other clients
		crypto.alpn_protocols = vec![b"h3".to_vec()];

		// TODO only set when 0-RTT enabled
		crypto.max_early_data_size = u32::MAX;
		crypto.send_half_rtt_data = ctx.cfg.zero_rtt_handshake;

		let mut config = ServerConfig::with_crypto(Arc::new(
			QuicServerConfig::try_from(crypto).context("no initial cipher suite found")?,
		));
		let mut tp_cfg = TransportConfig::default();

		tp_cfg
			.max_concurrent_bidi_streams(VarInt::from(ctx.cfg.experimental.max_concurrent_bidi_streams()))
			.max_concurrent_uni_streams(VarInt::from(ctx.cfg.experimental.max_concurrent_uni_streams()))
			.send_window(ctx.cfg.quic.send_window)
			.stream_receive_window(VarInt::from_u32(ctx.cfg.quic.receive_window))
			.max_idle_timeout(Some(
				IdleTimeout::try_from(ctx.cfg.quic.max_idle_time).map_err(|_| Error::InvalidMaxIdleTime)?,
			))
			.initial_mtu(ctx.cfg.quic.initial_mtu)
			.min_mtu(ctx.cfg.quic.min_mtu)
			.enable_segmentation_offload(ctx.cfg.quic.gso)
			.mtu_discovery_config(if !ctx.cfg.quic.pmtu { None } else { Some(Default::default()) });

		// Anti-probe: send QUIC PING frames to mimic real H3 server behavior
		if let Some(interval) = ctx.cfg.experimental.keep_alive_interval() {
			tp_cfg.keep_alive_interval(Some(interval));
		}

		let initial_window = ctx.cfg.quic.initial_window;
		let cc_factory: Arc<dyn ControllerFactory + Send + Sync> = match ctx.cfg.congestion_control {
			CongestionController::Bbr => {
				let mut bbr_config = BbrConfig::default();
				bbr_config.initial_window(initial_window);
				Arc::new(bbr_config)
			}
			CongestionController::Cubic => {
				let mut cubic_config = CubicConfig::default();
				cubic_config.initial_window(initial_window);
				Arc::new(cubic_config)
			}
			CongestionController::NewReno => {
				let mut new_reno = NewRenoConfig::default();
				new_reno.initial_window(initial_window);
				Arc::new(new_reno)
			}
			CongestionController::Bbr3 => {
				let mut bbr3_config = Bbr3Config::default();
				bbr3_config.initial_window(initial_window);
				Arc::new(bbr3_config)
			}
		};
		tp_cfg.congestion_controller_factory(Arc::new(SafePacingFactory::new(cc_factory)));

		config.transport_config(Arc::new(tp_cfg));

		let socket = {
			// Use IPv6 socket binding to [::] (all interfaces)
			// With dual_stack=true, this socket accepts BOTH IPv4 and IPv6 connections
			// IPv4 clients connect via IPv4-mapped IPv6 addresses (e.g.,
			// ::ffff:192.168.1.1)
			let bind_addr: SocketAddr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, ctx.cfg.server_port, 0, 0));

			let socket =
				Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).context("failed to create endpoint UDP socket")?;

			if ctx.cfg.dual_stack {
				// set_only_v6(false) enables dual-stack: IPv6 socket also accepts IPv4
				socket
					.set_only_v6(false)
					.map_err(|err| Error::Socket("endpoint dual-stack socket setting error", err))?;
			}

			socket
				.bind(&SockAddr::from(bind_addr))
				.context("failed to bind endpoint UDP socket")?;

			StdUdpSocket::from(socket)
		};

		let ep = Endpoint::new(EndpointConfig::default(), Some(config), socket, Arc::new(TokioRuntime))?;

		Ok(Self { ep, ctx })
	}

	pub async fn start(&self) {
		warn!("server started, listening on {}", self.ep.local_addr().unwrap());

		loop {
			match self.ep.accept().await {
				Some(conn) => match conn.accept() {
					Ok(conn) => {
						tokio::spawn(Connection::handle(self.ctx.clone(), conn));
					}
					Err(e) => {
						debug!("[Incoming] Failed to accept connection: {e}");
					}
				},
				None => {
					debug!("[Incoming] the endpoint is closed");
					return;
				}
			}
		}
	}
}
