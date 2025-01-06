// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;

use rand::Rng;

use super::{
    event::DhcpV4Event,
    time::{gen_dhcp_request_delay, gen_renew_rebind_times},
};
use crate::{
    event::DhcpEventPool,
    socket::{DhcpRawSocket, DhcpSocket, DhcpUdpSocket},
    DhcpError, DhcpV4Config, DhcpV4Lease, DhcpV4Message, DhcpV4MessageType,
    ErrorKind,
};

// RFC 2131 suggests four times(60 seconds) retry before fallback to
// discovery phase
const MAX_REQUEST_RETRY_COUNT: u32 = 4;

const NOT_RETRY: bool = false;
const IS_RETRY: bool = true;

#[derive(Debug, PartialEq, Clone, Copy)]
enum DhcpV4Phase {
    Done,
    Discovery,
    Request,
    Renew,
    Rebind,
}

impl Default for DhcpV4Phase {
    fn default() -> Self {
        Self::Discovery
    }
}

impl std::fmt::Display for DhcpV4Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Done => "done",
                Self::Discovery => "discovery",
                Self::Request => "request",
                Self::Renew => "renew",
                Self::Rebind => "rebind",
            }
        )
    }
}

#[derive(Debug)]
pub struct DhcpV4Client {
    config: DhcpV4Config,
    event_pool: DhcpEventPool<DhcpV4Event>,
    lease: Option<DhcpV4Lease>,
    phase: DhcpV4Phase,
    raw_socket: Option<DhcpRawSocket>,
    retry_count: u32,
    udp_socket: Option<DhcpUdpSocket>,
    xid: u32,
}

impl AsRawFd for DhcpV4Client {
    fn as_raw_fd(&self) -> RawFd {
        self.event_pool.epoll.as_raw_fd()
    }
}

impl DhcpV4Client {
    pub fn init(
        mut config: DhcpV4Config,
        lease: Option<DhcpV4Lease>,
    ) -> Result<Self, DhcpError> {
        config.init()?;
        let mut event_pool = DhcpEventPool::new()?;
        event_pool.add_timer(
            Duration::from_secs(config.timeout.into()),
            DhcpV4Event::Timeout,
        )?;
        let raw_socket = DhcpRawSocket::new(&config)?;
        event_pool
            .add_socket(raw_socket.as_raw_fd(), DhcpV4Event::RawPackageIn)?;

        let xid: u32 = rand::thread_rng().gen();

        let (dhcp_msg, phase) = if let Some(lease) = &lease {
            event_pool.add_timer(
                Duration::from_secs(gen_dhcp_request_delay(0).into()),
                DhcpV4Event::RequestTimeout,
            )?;
            let mut dhcp_msg =
                DhcpV4Message::new(&config, DhcpV4MessageType::Request, xid);
            dhcp_msg.load_lease(lease.clone());
            (dhcp_msg, DhcpV4Phase::Request)
        } else {
            event_pool.add_timer(
                Duration::from_secs(gen_dhcp_request_delay(0).into()),
                DhcpV4Event::DiscoveryTimeout,
            )?;
            (
                DhcpV4Message::new(&config, DhcpV4MessageType::Discovery, xid),
                DhcpV4Phase::Discovery,
            )
        };
        raw_socket.send(&dhcp_msg.to_eth_pkg_broadcast()?)?;
        Ok(Self {
            config,
            event_pool,
            lease,
            phase,
            xid,
            raw_socket: Some(raw_socket),
            retry_count: 0,
            udp_socket: None,
        })
    }

    fn clean_up(&mut self) {
        self.lease = None;
        self.retry_count = 0;
        self.phase = DhcpV4Phase::Done;
        self.event_pool.remove_all_event();
        self.raw_socket = None;
        self.udp_socket = None;
    }

    pub fn poll(&self, wait_time: u32) -> Result<Vec<DhcpV4Event>, DhcpError> {
        self.event_pool.poll(wait_time)
    }

    fn gen_discovery_pkg(&self) -> DhcpV4Message {
        DhcpV4Message::new(&self.config, DhcpV4MessageType::Discovery, self.xid)
    }

    fn gen_request_pkg(&self, lease: &DhcpV4Lease) -> DhcpV4Message {
        let mut dhcp_msg = DhcpV4Message::new(
            &self.config,
            DhcpV4MessageType::Request,
            self.xid,
        );
        dhcp_msg.load_lease(lease.clone());
        dhcp_msg
    }

    fn process_discovery(&mut self) -> Result<Option<DhcpV4Lease>, DhcpError> {
        let socket = if let Some(s) = self.raw_socket.as_ref() {
            s
        } else {
            self.clean_up();
            let e = DhcpError::new(
                ErrorKind::Bug,
                "process_discovery(): No Raw socket".to_string(),
            );
            log::error!("{}", e);
            return Err(e);
        };
        let lease =
            match recv_dhcp_msg(socket, DhcpV4MessageType::Offer, self.xid) {
                Ok(Some(l)) => l,
                Ok(None) => return Ok(None),
                Err(e) => {
                    log::info!("Ignoring invalid DHCP package: {e}");
                    return Ok(None);
                }
            };
        socket.send(&self.gen_request_pkg(&lease).to_eth_pkg_broadcast()?)?;
        self.lease = Some(lease);
        self.event_pool.add_timer(
            Duration::from_secs(gen_dhcp_request_delay(0).into()),
            DhcpV4Event::RequestTimeout,
        )?;
        self.retry_count = 0;
        self.event_pool.del_timer(DhcpV4Event::DiscoveryTimeout)?;
        self.phase = DhcpV4Phase::Request;
        Ok(None)
    }

    fn set_renew_rebind_timer(
        &mut self,
        lease: &DhcpV4Lease,
    ) -> Result<(), DhcpError> {
        let t = gen_renew_rebind_times(lease.t1, lease.t2, lease.lease_time);
        self.event_pool
            .add_timer(Duration::from_secs(t[0].into()), DhcpV4Event::Renew)?;
        self.event_pool.add_timer(
            Duration::from_secs(t[1].into()),
            DhcpV4Event::RenewRetry,
        )?;
        self.event_pool
            .add_timer(Duration::from_secs(t[2].into()), DhcpV4Event::Rebind)?;
        self.event_pool.add_timer(
            Duration::from_secs(t[3].into()),
            DhcpV4Event::RebindRetry,
        )?;
        self.event_pool.add_timer(
            Duration::from_secs(lease.lease_time.into()),
            DhcpV4Event::LeaseExpired,
        )?;
        Ok(())
    }

    fn process_request(&mut self) -> Result<Option<DhcpV4Lease>, DhcpError> {
        let socket = if let Some(s) = self.raw_socket.as_ref() {
            s
        } else {
            self.clean_up();
            let e = DhcpError::new(
                ErrorKind::Bug,
                "process_request(): No Raw socket".to_string(),
            );
            log::error!("{}", e);
            return Err(e);
        };
        let lease =
            match recv_dhcp_msg(socket, DhcpV4MessageType::Ack, self.xid) {
                Ok(Some(l)) => l,
                Ok(None) => return Ok(None),
                Err(e) => {
                    log::info!("Ignoring invalid DHCP package: {e}");
                    return Ok(None);
                }
            };
        self.clean_up();
        self.lease = Some(lease.clone());
        self.event_pool.del_timer(DhcpV4Event::RequestTimeout)?;
        self.set_renew_rebind_timer(&lease)?;
        Ok(Some(lease))
    }

    // RFC 2131 suggests four times(60 seconds) retry before fallback to
    // discovery phase
    fn process_request_timeout(
        &mut self,
    ) -> Result<Option<DhcpV4Lease>, DhcpError> {
        self.event_pool.del_timer(DhcpV4Event::RequestTimeout)?;
        if self.retry_count >= MAX_REQUEST_RETRY_COUNT {
            self.retry_count = 0;
            self.phase = DhcpV4Phase::Discovery;
            self.event_pool.add_timer(
                Duration::from_secs(
                    gen_dhcp_request_delay(self.retry_count).into(),
                ),
                DhcpV4Event::DiscoveryTimeout,
            )?;
            if let Some(raw_socket) = &self.raw_socket {
                raw_socket
                    .send(&self.gen_discovery_pkg().to_eth_pkg_broadcast()?)?;
                Ok(None)
            } else {
                self.clean_up();
                let e =
                    DhcpError::new(ErrorKind::Bug, "No RAW socket".to_string());
                log::error!("{}", e);
                Err(e)
            }
        } else {
            self.retry_count += 1;
            self.event_pool.add_timer(
                Duration::from_secs(
                    gen_dhcp_request_delay(self.retry_count).into(),
                ),
                DhcpV4Event::RequestTimeout,
            )?;
            if let Some(raw_socket) = &self.raw_socket {
                if let Some(lease) = &self.lease {
                    raw_socket.send(
                        &self.gen_request_pkg(lease).to_eth_pkg_broadcast()?,
                    )?;
                    Ok(None)
                } else {
                    self.clean_up();
                    let e = DhcpError::new(
                        ErrorKind::Bug,
                        "No lease in request timeout process".to_string(),
                    );
                    log::error!("{}", e);
                    Err(e)
                }
            } else {
                let e =
                    DhcpError::new(ErrorKind::Bug, "No RAW socket".to_string());
                log::error!("{}", e);
                Err(e)
            }
        }
    }

    fn process_discovery_timeout(
        &mut self,
    ) -> Result<Option<DhcpV4Lease>, DhcpError> {
        self.event_pool.del_timer(DhcpV4Event::RequestTimeout)?;
        self.retry_count += 1;
        self.event_pool.add_timer(
            Duration::from_secs(
                gen_dhcp_request_delay(self.retry_count).into(),
            ),
            DhcpV4Event::DiscoveryTimeout,
        )?;
        if let Some(raw_socket) = &self.raw_socket {
            raw_socket
                .send(&self.gen_discovery_pkg().to_eth_pkg_broadcast()?)?;
            Ok(None)
        } else {
            self.clean_up();
            let e = DhcpError::new(ErrorKind::Bug, "No RAW socket".to_string());
            log::error!("{}", e);
            Err(e)
        }
    }

    fn process_timeout(&mut self) -> Result<Option<DhcpV4Lease>, DhcpError> {
        self.clean_up();
        let e = DhcpError::new(ErrorKind::Timeout, "Timeout".to_string());
        log::error!("{}", e);
        Err(e)
    }

    // Unicast to DHCP server requesting lease extension, with ciaddr field
    // and empty server identifier.
    fn process_renew(
        &mut self,
        is_retry: bool,
    ) -> Result<Option<DhcpV4Lease>, DhcpError> {
        if is_retry {
            self.event_pool.del_timer(DhcpV4Event::RenewRetry)?;
        } else {
            self.event_pool.del_timer(DhcpV4Event::Renew)?;
        }
        // The renew require unicast to DHCP server which hard(need
        // ARP) to do in raw socket for proxy mode.
        // TODO: For now, we just skip renew stage and let the lease
        // been refreshed in rebind stage.
        if self.config.is_proxy {
            log::debug!("Proxy mode has no renew support yet, ignoring");
            return Ok(None);
        }

        let lease = if let Some(l) = self.lease.as_ref() {
            l
        } else {
            self.clean_up();
            let e = DhcpError::new(
                ErrorKind::Bug,
                "process_renew(): No lease".to_string(),
            );
            log::error!("{}", e);
            return Err(e);
        };
        let udp_socket = DhcpUdpSocket::new(
            self.config.iface_name.as_str(),
            &lease.yiaddr,
            &lease.siaddr,
            self.config.socket_timeout,
        )?;

        let mut dhcp_msg = DhcpV4Message::new(
            &self.config,
            DhcpV4MessageType::Request,
            self.xid,
        );
        dhcp_msg.load_lease(lease.clone());
        dhcp_msg.renew_or_rebind(true);
        udp_socket.send(&dhcp_msg.to_dhcp_pkg()?)?;
        self.event_pool
            .add_socket(udp_socket.as_raw_fd(), DhcpV4Event::UdpPackageIn)?;
        self.udp_socket = Some(udp_socket);
        self.phase = DhcpV4Phase::Renew;
        self.retry_count = u32::from(is_retry);
        Ok(None)
    }

    fn process_renew_recv(&mut self) -> Result<Option<DhcpV4Lease>, DhcpError> {
        let socket = if let Some(s) = self.udp_socket.as_ref() {
            s
        } else {
            self.clean_up();
            let e = DhcpError::new(
                ErrorKind::Bug,
                "process_renew_recv(): No UDP socket".to_string(),
            );
            log::error!("{}", e);
            return Err(e);
        };
        match recv_dhcp_msg(socket, DhcpV4MessageType::Ack, self.xid) {
            Ok(Some(lease)) => {
                self.clean_up();
                self.lease = Some(lease.clone());
                self.set_renew_rebind_timer(&lease)?;
                Ok(Some(lease))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                if self.retry_count == 0 {
                    log::warn!("DHCP renew failed: {}, will try", e);
                } else {
                    log::warn!("DHCP renew failed twice: {}, will rebind", e);
                }
                Ok(None)
            }
        }
    }

    // Broadcast to all DHCP servers requesting lease extension with ciaddr.
    fn process_rebind(
        &mut self,
        is_retry: bool,
    ) -> Result<Option<DhcpV4Lease>, DhcpError> {
        if is_retry {
            self.event_pool.del_timer(DhcpV4Event::RebindRetry)?;
        } else {
            self.event_pool.del_timer(DhcpV4Event::Rebind)?;
        }
        let lease = if let Some(l) = self.lease.as_ref() {
            l
        } else {
            self.clean_up();
            let e = DhcpError::new(
                ErrorKind::Bug,
                "process_rebind(): no lease".to_string(),
            );
            log::error!("{}", e);
            return Err(e);
        };
        let raw_socket = DhcpRawSocket::new(&self.config)?;
        let mut dhcp_msg = DhcpV4Message::new(
            &self.config,
            DhcpV4MessageType::Request,
            self.xid,
        );
        dhcp_msg.load_lease(lease.clone());
        dhcp_msg.renew_or_rebind(true);
        raw_socket.send(&dhcp_msg.to_eth_pkg_broadcast()?)?;
        self.event_pool
            .add_socket(raw_socket.as_raw_fd(), DhcpV4Event::RawPackageIn)?;
        self.raw_socket = Some(raw_socket);
        self.phase = DhcpV4Phase::Rebind;
        self.retry_count = u32::from(is_retry);
        Ok(None)
    }

    fn process_rebind_recv(
        &mut self,
    ) -> Result<Option<DhcpV4Lease>, DhcpError> {
        let socket = if let Some(s) = self.raw_socket.as_ref() {
            s
        } else {
            self.clean_up();
            let e = DhcpError::new(
                ErrorKind::Bug,
                "process_rebind_recv(): No RAW socket".to_string(),
            );
            log::error!("{}", e);
            return Err(e);
        };
        match recv_dhcp_msg(socket, DhcpV4MessageType::Ack, self.xid) {
            Ok(Some(lease)) => {
                self.clean_up();
                self.lease = Some(lease.clone());
                self.set_renew_rebind_timer(&lease)?;
                Ok(Some(lease))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                if self.retry_count == 0 {
                    log::warn!("DHCP rebind failed: {}, will try", e);
                } else {
                    log::warn!(
                        "DHCP rebind failed twice: {}, will request new lease",
                        e
                    );
                }
                Ok(None)
            }
        }
    }

    // Instead raise error to user, we should try the whole DHCP discovery
    // again with specific timeout
    fn process_lease_expired(
        &mut self,
    ) -> Result<Option<DhcpV4Lease>, DhcpError> {
        self.clean_up();
        self.event_pool.add_timer(
            Duration::from_secs(self.config.timeout.into()),
            DhcpV4Event::Timeout,
        )?;
        let raw_socket = DhcpRawSocket::new(&self.config)?;
        self.event_pool
            .add_socket(raw_socket.as_raw_fd(), DhcpV4Event::RawPackageIn)?;
        self.event_pool.add_timer(
            Duration::from_secs(gen_dhcp_request_delay(0).into()),
            DhcpV4Event::DiscoveryTimeout,
        )?;
        let dhcp_msg = DhcpV4Message::new(
            &self.config,
            DhcpV4MessageType::Discovery,
            self.xid,
        );
        raw_socket.send(&dhcp_msg.to_eth_pkg_broadcast()?)?;
        self.raw_socket = Some(raw_socket);
        self.phase = DhcpV4Phase::Discovery;
        Ok(None)
    }

    pub fn process(
        &mut self,
        event: DhcpV4Event,
    ) -> Result<Option<DhcpV4Lease>, DhcpError> {
        log::debug!("Processing event {:?}", event);
        match event {
            DhcpV4Event::RawPackageIn => match self.phase {
                DhcpV4Phase::Discovery => self.process_discovery(),
                DhcpV4Phase::Request => self.process_request(),
                DhcpV4Phase::Rebind => self.process_rebind_recv(),
                _ => {
                    log::error!(
                        "BUG: Got in-coming packet on raw socket \
                        with unexpected phase {}",
                        self.phase
                    );
                    Ok(None)
                }
            },
            DhcpV4Event::UdpPackageIn => match self.phase {
                DhcpV4Phase::Renew => self.process_renew_recv(),
                _ => {
                    log::error!(
                        "BUG: Got in-coming packet on UDP socket \
                        with unexpected phase {}",
                        self.phase
                    );
                    Ok(None)
                }
            },
            DhcpV4Event::RequestTimeout => self.process_request_timeout(),
            DhcpV4Event::DiscoveryTimeout => self.process_discovery_timeout(),
            DhcpV4Event::Timeout => self.process_timeout(),
            DhcpV4Event::Renew => self.process_renew(NOT_RETRY),
            DhcpV4Event::RenewRetry => self.process_renew(IS_RETRY),
            DhcpV4Event::Rebind => self.process_rebind(NOT_RETRY),
            DhcpV4Event::RebindRetry => self.process_rebind(IS_RETRY),
            DhcpV4Event::LeaseExpired => self.process_lease_expired(),
        }
    }

    /// Release the DHCPv4 lease.
    /// To request new lease once released, please create new instance of
    /// [DhcpV4Client].
    pub fn release(&mut self, lease: &DhcpV4Lease) -> Result<(), DhcpError> {
        let mut dhcp_msg = DhcpV4Message::new(
            &self.config,
            DhcpV4MessageType::Release,
            self.xid,
        );
        dhcp_msg.load_lease(lease.clone());

        if self.config.is_proxy {
            let raw_socket = DhcpRawSocket::new(&self.config)?;
            raw_socket.send(&dhcp_msg.to_proxy_eth_pkg_unicast()?)?;
        } else {
            // Cannot create UDP socket when interface does not have DHCP IP
            // assigned, so we fallback to RAW socket
            match DhcpUdpSocket::new(
                self.config.iface_name.as_str(),
                &lease.yiaddr,
                &lease.siaddr,
                self.config.socket_timeout,
            ) {
                Ok(udp_socket) => {
                    udp_socket.send(&dhcp_msg.to_dhcp_pkg()?)?;
                }
                Err(e) => {
                    log::debug!(
                        "Failed to create UDP socket to release lease {e}, \
                        fallback to RAW socket"
                    );
                    let raw_socket = DhcpRawSocket::new(&self.config)?;
                    raw_socket.send(&dhcp_msg.to_proxy_eth_pkg_unicast()?)?;
                }
            }
        }
        self.clean_up();
        Ok(())
    }
}

fn recv_dhcp_msg(
    socket: &impl DhcpSocket,
    expected: DhcpV4MessageType,
    xid: u32,
) -> Result<Option<DhcpV4Lease>, DhcpError> {
    let buffer: Vec<u8> = socket.recv()?;
    let reply_dhcp_msg = if socket.is_raw() {
        DhcpV4Message::from_eth_pkg(&buffer)?
    } else {
        DhcpV4Message::from_dhcp_pkg(&buffer)?
    };
    if reply_dhcp_msg.xid != xid {
        log::debug!(
            "Dropping DHCP message due to xid miss-match. \
            Expecting {}, got {}",
            xid,
            reply_dhcp_msg.xid
        );
        return Ok(None);
    }
    if reply_dhcp_msg.msg_type != expected {
        log::debug!(
            "Dropping DHCP message due to type miss-match.
            Expecting {}, got {}",
            expected,
            reply_dhcp_msg.msg_type
        );
        return Ok(None);
    }
    if let Some(lease) = reply_dhcp_msg.lease {
        Ok(Some(lease))
    } else {
        log::debug!(
            "No lease found in the reply from DHCP server {:?}",
            reply_dhcp_msg
        );
        Ok(None)
    }
}
