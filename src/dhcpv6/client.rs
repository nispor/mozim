// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use super::{
    msg::{DhcpV6Message, DhcpV6MessageType},
    socket::DhcpUdpV6Socket,
};
use crate::{
    DhcpError, DhcpTimer, DhcpV6Config, DhcpV6Lease, DhcpV6Mode, DhcpV6State,
    ErrorKind,
};

/// DHCPv6 Client
///
/// Implementation require tokio runtime with these features enabled:
///  * `tokio::runtime::Builder::enable_time()`
///  * `tokio::runtime::Builder::enable_io()`
///
/// Example code:
/// ```no_run
/// #[tokio::main(flavor = "current_thread")]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = mozim::DhcpV6Config::new(
///         "eth1", mozim::DhcpV6Mode::NonTemporaryAddresses);
///     let mut cli = mozim::DhcpV6Client::init(config, None).await.unwrap();
///
///     loop {
///         let state = cli.run().await?;
///         println!("DHCP state {state}");
///         if let mozim::DhcpV6State::Done(lease) = state {
///             println!("Got lease {lease:?}");
///         }
///     }
/// }
/// ```
#[derive(Debug)]
pub struct DhcpV6Client {
    pub(crate) config: DhcpV6Config,
    pub(crate) lease: Option<DhcpV6Lease>,
    pub(crate) state: DhcpV6State,
    pub(crate) xid: u32,
    pub(crate) pending_lease: Option<DhcpV6Lease>,
    pub(crate) udp_socket: Option<DhcpUdpV6Socket>,
    pub(crate) retransmit_count: u32,
    pub(crate) trans_begin_time: Instant,
    pub(crate) retransmit_timeout: Duration,
    pub(crate) t1_timer: Option<DhcpTimer>,
    pub(crate) t2_timer: Option<DhcpTimer>,
    pub(crate) valid_timer: Option<DhcpTimer>,
    error: Option<DhcpError>,
    timeout_timer: Option<DhcpTimer>,
}

impl DhcpV6Client {
    pub async fn init(
        mut config: DhcpV6Config,
        lease: Option<DhcpV6Lease>,
    ) -> Result<Self, DhcpError> {
        if config.need_resolve() {
            config.resolve().await?;
        }

        let state = if lease.is_some() {
            // TODO(Gris Ge): We need to check whether the lease still valid,
            // if not valid, we should run Solicit with hint in preferred
            // address: RFC 8415, 18.2.1. Creation and Transmission of Solicit
            // Messages:
            //      The client MAY include addresses in IA Address options (see
            //      Section 21.6) encapsulated within IA_NA and IA_TA options
            //      as hints to the server about the addresses for which the
            //      client has a preference.
            //      The client MAY include values in IA Prefix options (see
            //      Section 21.22) encapsulated within IA_PD options as hints
            //      for the delegated prefix and/or prefix length for which the
            //      client has a preference.  See Section 18.2.4 for more on
            //      prefix-length hints.
            DhcpV6State::Renew
        } else {
            DhcpV6State::Solicit
        };

        Ok(Self {
            config,
            lease,
            state,
            // In RFC 8415, the `transaction-id` is a 3-octet field
            xid: rand::random_range(0..0x00FFFFFF),
            pending_lease: Default::default(),
            udp_socket: Default::default(),
            retransmit_count: Default::default(),
            trans_begin_time: Instant::now(),
            retransmit_timeout: Duration::new(0, 0),
            t1_timer: Default::default(),
            t2_timer: Default::default(),
            valid_timer: Default::default(),
            error: Default::default(),
            timeout_timer: None,
        })
    }

    pub(crate) fn regen_xid(&mut self) {
        self.xid = rand::random_range(0..0x00FFFFFF);
    }

    /// Please run this function in a loop so it could refresh the lease with
    /// DHCP server.
    /// Return whenever state change or error.
    /// Repeat run() after error will emit the same error again until
    /// [DhcpV6Client::clean_up()] been invoked.
    pub async fn run(&mut self) -> Result<DhcpV6State, DhcpError> {
        if let Some(e) = self.error.as_ref() {
            log::error!(
                "Previous error found, please run DhcpV6Client::clean_up() if \
                 you want to start the DHCP process again"
            );
            // Sleep 5 seconds to prevent infinite loop
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            Err(e.clone())
        } else if !self.state.is_done() && self.config.timeout_sec != 0 {
            let remains = if let Some(t) = self.timeout_timer.as_ref() {
                t.remains()?
            } else {
                std::time::Duration::from_secs(self.config.timeout_sec.into())
            };
            tokio::select! {
                _ = tokio::time::sleep(remains) => {
                    let e = DhcpError::new(
                        ErrorKind::Timeout,
                        format!(
                            "Timeout on acquiring DHCPv6 lease on {}",
                            &self.config.iface_name
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

    async fn run_without_timeout(&mut self) -> Result<DhcpV6State, DhcpError> {
        let result = match self.state {
            DhcpV6State::Solicit => self.solicit().await,
            DhcpV6State::Request => self.request().await,
            DhcpV6State::Renew => self.renew().await,
            DhcpV6State::Rebind => self.rebind().await,
            DhcpV6State::Done(_) => self.wait_timer().await,
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
        lease: &DhcpV6Lease,
    ) -> Result<(), DhcpError> {
        // RFC 8415 suggest client do retransmission if no reply from DHCP
        // server, but still allows client terminate the procedure
        // early.
        // TODO(Gris Ge): Wait reply from DHCP server and retry.
        let mut dhcp_msg = DhcpV6Message::new(
            DhcpV6MessageType::Release,
            self.xid,
            &self.config.duid,
            &Instant::now(),
        );
        dhcp_msg.load_lease(lease);
        let udp_socket = self.get_udp_socket_or_init().await?;
        udp_socket.send_multicast(&dhcp_msg.emit()).await?;
        self.clean_up();
        Ok(())
    }

    pub fn clean_up(&mut self) {
        self.state = DhcpV6State::Solicit;
        self.lease = None;
        self.pending_lease = None;
        self.udp_socket = None;
        self.t1_timer = None;
        self.t2_timer = None;
        self.valid_timer = None;
        self.error = None;
        self.retransmit_count = 0;
        self.retransmit_timeout = Duration::new(0, 0);
    }

    pub fn reset_retransmit_counters(&mut self) {
        self.retransmit_count = 0;
        self.retransmit_timeout = Duration::new(0, 0);
        self.trans_begin_time = Instant::now();
    }

    pub fn done(&mut self, lease: DhcpV6Lease) -> Result<(), DhcpError> {
        self.set_lease_timer(&lease)?;
        self.reset_retransmit_counters();
        self.timeout_timer = None;
        self.udp_socket = None;
        self.pending_lease = None;
        self.lease = Some(lease.clone());
        self.state = DhcpV6State::Done(Box::new(lease));
        Ok(())
    }

    pub(crate) async fn get_udp_socket_or_init(
        &mut self,
    ) -> Result<&mut DhcpUdpV6Socket, DhcpError> {
        if self.udp_socket.is_none() {
            self.udp_socket = Some(
                DhcpUdpV6Socket::new(
                    self.config.iface_name.as_str(),
                    self.config.iface_index,
                    self.config.src_ip,
                )
                .await?,
            );
        }
        Ok(self.udp_socket.as_mut().unwrap())
    }

    async fn wait_timer(&mut self) -> Result<(), DhcpError> {
        let timer = if self.config.mode == DhcpV6Mode::TemporaryAddresses {
            self.valid_timer.as_ref()
        } else {
            self.t1_timer.as_ref()
        };
        if let Some(timer) = timer {
            timer.wait().await?;
            self.reset_retransmit_counters();
            if self.config.mode == DhcpV6Mode::TemporaryAddresses {
                self.state = DhcpV6State::Solicit;
            } else {
                self.state = DhcpV6State::Renew;
            }
        } else {
            log::error!("BUG: wait_timer() got no timer: {self:?}");
            self.reset_retransmit_counters();
            self.state = DhcpV6State::Solicit;
        }
        Ok(())
    }
}
