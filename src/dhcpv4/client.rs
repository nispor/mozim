// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use super::{
    socket::{DhcpRawSocket, DhcpUdpV4Socket, DhcpV4Socket},
    DhcpV4Message,
};
use crate::{
    DhcpError, DhcpTimer, DhcpV4Config, DhcpV4Lease, DhcpV4State, ErrorKind,
};

/// DHCPv4 Client
///
/// Implementation require tokio runtime with these features enabled:
///  * `tokio::runtime::Builder::enable_time()`
///  * `tokio::runtime::Builder::enable_io()`
///
/// Example code:
/// ```no_run
/// #[tokio::main(flavor = "current_thread")]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = mozim::DhcpV4Config::new("eth1");
///     let mut cli = mozim::DhcpV4Client::init(config, None).await.unwrap();
///
///     loop {
///         let state = cli.run().await?;
///         println!("DHCP state {state}");
///         if let mozim::DhcpV4State::Done(lease) = state {
///             println!("Got lease {lease:?}");
///         }
///     }
/// }
/// ```
#[derive(Debug, Default)]
pub struct DhcpV4Client {
    pub(crate) config: DhcpV4Config,
    pub(crate) lease: Option<DhcpV4Lease>,
    pub(crate) pending_lease: Option<DhcpV4Lease>,
    pub(crate) state: DhcpV4State,
    pub(crate) raw_socket: Option<DhcpRawSocket>,
    pub(crate) udp_socket: Option<DhcpUdpV4Socket>,
    pub(crate) retry_count: u32,
    pub(crate) xid: u32,
    pub(crate) t1_timer: Option<DhcpTimer>,
    pub(crate) t2_timer: Option<DhcpTimer>,
    pub(crate) lease_timer: Option<DhcpTimer>,
    pub(crate) timeout_timer: Option<DhcpTimer>,
    /// Start time of the current address acquisition or renewal process,
    /// used to fill the DHCPv4 header's `secs` field.
    pub(crate) trans_start_time: Option<Instant>,
    /// `secs` value of the DHCPDISCOVER message which the pending
    /// DHCPOFFER replies to, `None` when no DHCPDISCOVER has been sent
    /// yet. RFC 2131 section 3.1 requires the DHCPREQUEST to use the same
    /// value.
    pub(crate) discovery_secs: Option<u16>,
    error: Option<DhcpError>,
}

impl DhcpV4Client {
    pub async fn init(
        mut config: DhcpV4Config,
        lease: Option<DhcpV4Lease>,
    ) -> Result<Self, DhcpError> {
        if config.need_resolve() {
            config.resolve().await?;
        }

        let state = if lease.is_some() {
            DhcpV4State::Selecting
        } else {
            DhcpV4State::InitReboot
        };

        let xid = rand::random();

        Ok(Self {
            config,
            lease,
            state,
            xid,
            ..Default::default()
        })
    }

    /// Please run this function in a loop so it could refresh the lease with
    /// DHCP server.
    /// Return whenever state change or error.
    /// Repeat run() after error will emit the same error again until
    /// [DhcpV4Client::clean_up()] been invoked.
    pub async fn run(&mut self) -> Result<DhcpV4State, DhcpError> {
        if let Some(e) = self.error.as_ref() {
            log::error!(
                "Previous error found, please run DhcpV4Client::clean_up() if \
                 you want to start the DHCP process again"
            );
            // Sleep 5 seconds to prevent infinite loop
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            Err(e.clone())
        } else if !self.state.is_done() && self.config.timeout_sec != 0 {
            let remains = self.get_timeout_remains()?;
            tokio::select! {
                _ = tokio::time::sleep(remains) => {
                    let e = DhcpError::new(
                        ErrorKind::Timeout,
                        format!(
                            "Timeout on acquiring DHCPv4 lease on {}",
                            self.config.iface_name
                        )
                    );
                    self.error = Some(e.clone());
                    Err(e)
                },
                result = self.run_without_timeout() => {
                    result
                }
            }
        } else {
            self.run_without_timeout().await
        }
    }

    fn get_timeout_remains(&mut self) -> Result<Duration, DhcpError> {
        if self.timeout_timer.is_none() {
            self.timeout_timer = Some(DhcpTimer::new(Duration::from_secs(
                self.config.timeout_sec.into(),
            ))?);
        }
        self.timeout_timer.as_ref().unwrap().remains()
    }

    pub(crate) fn start_trans_timer(&mut self) {
        self.trans_start_time = Some(Instant::now());
    }

    /// Elapsed seconds of the current DHCPv4 transaction, used to fill
    /// the `secs` header field.
    ///
    /// RFC 2131 section 2: the `secs` header field is filled in by the
    /// client with the seconds elapsed since it began address acquisition
    /// or renewal, Table 5 (section 4.4.1) permits either 0 or that
    /// value. The timer starts on first use, so a client which does not
    /// start with a DHCPDISCOVER still counts from its first message.
    /// The field is 16 bits wide, so saturate instead of wrapping around.
    pub(crate) fn trans_elapsed_secs(&mut self) -> u16 {
        let start_time =
            *self.trans_start_time.get_or_insert_with(Instant::now);
        u16::try_from(start_time.elapsed().as_secs()).unwrap_or(u16::MAX)
    }

    /// The `secs` header field value for the DHCPREQUEST message.
    ///
    /// RFC 2131 section 3.1:
    ///     To help ensure that any BOOTP relay agents forward the
    ///     DHCPREQUEST message to the same set of DHCP servers that
    ///     received the original DHCPDISCOVER message, the DHCPREQUEST
    ///     message MUST use the same value in the DHCP message header's
    ///     'secs' field and be sent to the same IP broadcast address as
    ///     the original DHCPDISCOVER message.
    ///
    /// The DHCPDISCOVER value is deliberately kept instead of counting
    /// forward, not even when the DHCPREQUEST is retransmitted.
    pub(crate) fn gen_request_secs(&mut self) -> u16 {
        match self.discovery_secs {
            Some(secs) => secs,
            // RFC 2131 Table 5 allows using the seconds since this DHCP
            // process started when no DHCPDISCOVER message was sent, e.g.
            // when the client starts with an existing lease.
            None => self.trans_elapsed_secs(),
        }
    }

    async fn run_without_timeout(&mut self) -> Result<DhcpV4State, DhcpError> {
        let result = match self.state {
            DhcpV4State::InitReboot => self.discovery().await,
            DhcpV4State::Selecting => self.request().await,
            DhcpV4State::Renewing => self.renew().await,
            DhcpV4State::Rebinding => self.rebind().await,
            DhcpV4State::Done(_) => self.wait_t1_timer().await,
        };
        if let Err(e) = result {
            self.error = Some(e.clone());
            Err(e)
        } else {
            Ok(self.state.clone())
        }
    }

    pub async fn release(
        &mut self,
        lease: &DhcpV4Lease,
    ) -> Result<(), DhcpError> {
        let dhcp_msg =
            DhcpV4Message::new_release(self.xid, &self.config, lease);
        if self.config.is_proxy {
            self.get_raw_socket_or_init()
                .await?
                .send(&dhcp_msg.to_proxy_eth_packet_unicast(lease)?)
                .await?;
        } else {
            // Cannot create UDP socket when interface does not have DHCP IP
            // assigned, so we fallback to RAW socket
            match self.get_udp_socket_or_init().await {
                Ok(udp_socket) => {
                    udp_socket.send(&dhcp_msg.to_dhcp_packet()?).await?;
                }
                Err(e) => {
                    log::debug!(
                        "Failed to create UDP socket to release lease {e}, \
                         fallback to RAW socket"
                    );
                    self.get_raw_socket_or_init()
                        .await?
                        .send(&dhcp_msg.to_proxy_eth_packet_unicast(lease)?)
                        .await?;
                }
            }
        }
        self.clean_up();
        Ok(())
    }

    pub fn clean_up(&mut self) {
        self.state = DhcpV4State::InitReboot;
        self.lease = None;
        self.pending_lease = None;
        self.udp_socket = None;
        self.raw_socket = None;
        self.t1_timer = None;
        self.t2_timer = None;
        self.lease_timer = None;
        self.timeout_timer = None;
        self.trans_start_time = None;
        self.discovery_secs = None;
        self.error = None;
    }

    pub fn done(&mut self, lease: DhcpV4Lease) -> Result<(), DhcpError> {
        lease.validate()?;
        self.set_lease_timer(&lease)?;
        self.timeout_timer = None;
        self.raw_socket = None;
        self.udp_socket = None;
        self.pending_lease = None;
        self.lease = Some(lease.clone());
        self.retry_count = 0;
        self.trans_start_time = None;
        self.discovery_secs = None;
        self.state = DhcpV4State::Done(Box::new(lease));
        Ok(())
    }

    pub(crate) async fn get_udp_socket_or_init(
        &mut self,
    ) -> Result<&mut DhcpUdpV4Socket, DhcpError> {
        if self.udp_socket.is_none() {
            if let Some(lease) = self.lease.as_ref() {
                self.udp_socket = Some(
                    DhcpUdpV4Socket::new(
                        self.config.iface_name.as_str(),
                        lease.yiaddr,
                        lease.srv_id,
                    )
                    .await?,
                );
            } else {
                return Err(DhcpError::new(
                    ErrorKind::Bug,
                    format!(
                        "get_udp_socket_or_init() been invoked without lease: \
                         {self:?}"
                    ),
                ));
            }
        }
        Ok(self.udp_socket.as_mut().unwrap())
    }

    pub(crate) async fn get_raw_socket_or_init(
        &mut self,
    ) -> Result<&mut DhcpRawSocket, DhcpError> {
        if self.raw_socket.is_none() {
            self.raw_socket = Some(DhcpRawSocket::new(&self.config)?);
        }

        Ok(self.raw_socket.as_mut().unwrap())
    }

    async fn wait_t1_timer(&mut self) -> Result<(), DhcpError> {
        if let Some(t1_timer) = self.t1_timer.as_ref() {
            t1_timer.wait().await?;
            self.state = DhcpV4State::Renewing;
        } else {
            log::error!("BUG: wait_t1_timer() got no T1 timer: {self:?}");
            self.state = DhcpV4State::InitReboot;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_timeout_timer_spans_run_calls() {
        let mut config = DhcpV4Config::new("eth1");
        config.set_timeout_sec(1);
        let mut cli = DhcpV4Client {
            config,
            ..Default::default()
        };
        let first = cli.get_timeout_remains().unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let second = cli.get_timeout_remains().unwrap();
        assert!(
            second < first,
            "timeout should decrease across run() calls: {first:?} -> \
             {second:?}"
        );
    }

    #[test]
    fn test_clean_up_resets_timeout_timer() {
        let mut config = DhcpV4Config::new("eth1");
        config.set_timeout_sec(1);
        let mut cli = DhcpV4Client {
            config,
            ..Default::default()
        };
        cli.get_timeout_remains().unwrap();
        assert!(cli.timeout_timer.is_some());
        cli.clean_up();
        assert!(cli.timeout_timer.is_none());
    }

    #[test]
    fn test_clean_up_resets_secs() {
        let mut cli = DhcpV4Client::default();
        cli.start_trans_timer();
        cli.discovery_secs = Some(42);
        assert_eq!(cli.trans_elapsed_secs(), 0);
        assert_eq!(cli.gen_request_secs(), 42);

        cli.clean_up();

        assert!(cli.trans_start_time.is_none());
        assert_eq!(cli.discovery_secs, None);
        assert_eq!(cli.trans_elapsed_secs(), 0);
    }

    #[test]
    fn test_secs_saturates_at_u16_max() {
        let mut cli = DhcpV4Client {
            trans_start_time: Some(
                Instant::now() - Duration::from_secs(u64::from(u16::MAX) + 1),
            ),
            ..Default::default()
        };
        assert_eq!(cli.trans_elapsed_secs(), u16::MAX);
    }

    #[test]
    fn test_secs_starts_on_first_use() {
        let mut cli = DhcpV4Client::default();
        assert!(cli.trans_start_time.is_none());
        assert_eq!(cli.trans_elapsed_secs(), 0);
        assert!(cli.trans_start_time.is_some());
    }

    #[test]
    fn test_gen_request_secs_reuses_discovery_secs() {
        let mut cli = DhcpV4Client {
            trans_start_time: Some(Instant::now() - Duration::from_secs(70)),
            discovery_secs: Some(3),
            ..Default::default()
        };
        // RFC 2131 section 3.1: the DHCPREQUEST MUST reuse the
        // DHCPDISCOVER `secs` value even when much more time has elapsed.
        assert_eq!(cli.gen_request_secs(), 3);
    }

    #[test]
    fn test_gen_request_secs_without_discovery_counts_from_start() {
        let mut cli = DhcpV4Client::default();
        assert_eq!(cli.gen_request_secs(), 0);
        cli.trans_start_time = Some(Instant::now() - Duration::from_secs(70));
        assert_eq!(cli.gen_request_secs(), 70);
    }

    #[test]
    fn test_done_rejects_zero_t1() {
        let mut lease = DhcpV4Lease::default();
        lease.t2_sec = 60;
        lease.lease_time_sec = 100;
        let mut cli = DhcpV4Client::default();
        let err = cli.done(lease).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidDhcpMessage);
        assert!(
            err.msg().contains("T1"),
            "unexpected error message: {}",
            err.msg()
        );
    }

    #[test]
    fn test_done_rejects_zero_t2() {
        let mut lease = DhcpV4Lease::default();
        lease.t1_sec = 30;
        lease.lease_time_sec = 100;
        let mut cli = DhcpV4Client::default();
        let err = cli.done(lease).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidDhcpMessage);
        assert!(
            err.msg().contains("T2"),
            "unexpected error message: {}",
            err.msg()
        );
    }

    #[test]
    fn test_done_rejects_t1_not_earlier_than_t2() {
        let mut lease = DhcpV4Lease::default();
        lease.t1_sec = 60;
        lease.t2_sec = 60;
        lease.lease_time_sec = 100;
        let mut cli = DhcpV4Client::default();
        let err = cli.done(lease).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidDhcpMessage);
        assert!(
            err.msg().contains("T1"),
            "unexpected error message: {}",
            err.msg()
        );
    }

    #[test]
    fn test_done_rejects_t2_not_earlier_than_lease_time() {
        let mut lease = DhcpV4Lease::default();
        lease.t1_sec = 30;
        lease.t2_sec = 100;
        lease.lease_time_sec = 100;
        let mut cli = DhcpV4Client::default();
        let err = cli.done(lease).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidDhcpMessage);
        assert!(
            err.msg().contains("T2"),
            "unexpected error message: {}",
            err.msg()
        );
    }

    #[test]
    fn test_done_accepts_valid_manual_lease() {
        let mut lease = DhcpV4Lease::default();
        lease.t1_sec = 30;
        lease.t2_sec = 60;
        lease.lease_time_sec = 100;
        let mut cli = DhcpV4Client::default();
        cli.done(lease).unwrap();
        assert!(cli.t1_timer.is_some());
        assert!(cli.t2_timer.is_some());
        assert!(cli.lease_timer.is_some());
        assert!(cli.lease.is_some());
        assert!(matches!(cli.state, DhcpV4State::Done(_)));
    }
}
