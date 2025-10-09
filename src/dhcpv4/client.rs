// SPDX-License-Identifier: Apache-2.0

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
                            "Timeout on acquiring DHCPv4 lease on {}",
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
        self.error = None;
    }

    pub fn done(&mut self, lease: DhcpV4Lease) -> Result<(), DhcpError> {
        self.set_lease_timer(&lease)?;
        self.timeout_timer = None;
        self.raw_socket = None;
        self.udp_socket = None;
        self.pending_lease = None;
        self.lease = Some(lease.clone());
        self.retry_count = 0;
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
                        lease.siaddr,
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
