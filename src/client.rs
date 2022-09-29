use std::os::unix::io::{AsRawFd, RawFd};

use crate::{
    event::{DhcpEventPool, DhcpV4Event},
    socket::{DhcpRawSocket, DhcpSocket, DhcpUdpSocket},
    time::{gen_dhcp_request_delay, gen_renew_rebind_times},
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

#[derive(Debug)]
pub struct DhcpV4Client {
    config: DhcpV4Config,
    event_pool: DhcpEventPool,
    lease: Option<DhcpV4Lease>,
    phase: DhcpV4Phase,
    raw_socket: Option<DhcpRawSocket>,
    retry_count: u32,
    udp_socket: Option<DhcpUdpSocket>,
}

impl AsRawFd for DhcpV4Client {
    fn as_raw_fd(&self) -> RawFd {
        self.event_pool.epoll.as_raw_fd()
    }
}

impl DhcpV4Client {
    pub fn init(
        config: DhcpV4Config,
        lease: Option<DhcpV4Lease>,
    ) -> Result<Self, DhcpError> {
        let mut event_pool = DhcpEventPool::new()?;
        event_pool.add_timer(config.timeout, DhcpV4Event::Timeout)?;
        let raw_socket = DhcpRawSocket::new(&config)?;
        event_pool
            .add_socket(raw_socket.as_raw_fd(), DhcpV4Event::RawPackageIn)?;

        let (dhcp_msg, phase) = if let Some(lease) = &lease {
            event_pool.add_timer(
                gen_dhcp_request_delay(0),
                DhcpV4Event::RequestTimeout,
            )?;
            let mut dhcp_msg =
                DhcpV4Message::new(&config, DhcpV4MessageType::Request);
            dhcp_msg.load_lease(lease.clone());
            (dhcp_msg, DhcpV4Phase::Request)
        } else {
            event_pool.add_timer(
                gen_dhcp_request_delay(0),
                DhcpV4Event::DiscoveryTimeout,
            )?;
            (
                DhcpV4Message::new(&config, DhcpV4MessageType::Discovery),
                DhcpV4Phase::Discovery,
            )
        };
        raw_socket.send(&dhcp_msg.to_eth_pkg()?)?;
        Ok(Self {
            config,
            event_pool,
            lease,
            phase,
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

    pub fn poll(
        &self,
        wait_time: isize,
    ) -> Result<Vec<DhcpV4Event>, DhcpError> {
        self.event_pool.poll(wait_time)
    }

    fn gen_discovery_pkg(&self) -> DhcpV4Message {
        DhcpV4Message::new(&self.config, DhcpV4MessageType::Discovery)
    }

    fn gen_request_pkg(&self, lease: &DhcpV4Lease) -> DhcpV4Message {
        let mut dhcp_msg =
            DhcpV4Message::new(&self.config, DhcpV4MessageType::Request);
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
        let lease = match recv_dhcp_msg(socket, DhcpV4MessageType::Offer) {
            Ok(l) => l,
            Err(_) => {
                // We should not fail the action but let it retry and timeout
                return Ok(None);
            }
        };
        self.phase = DhcpV4Phase::Request;
        socket.send(&self.gen_request_pkg(&lease).to_eth_pkg()?)?;
        // TODO: Handle retry on failure
        Ok(None)
    }

    fn set_renew_rebind_timer(
        &mut self,
        lease: &DhcpV4Lease,
    ) -> Result<(), DhcpError> {
        let t = gen_renew_rebind_times(lease.t1, lease.t2, lease.lease_time);
        self.event_pool.add_timer(t[0], DhcpV4Event::Renew)?;
        self.event_pool.add_timer(t[1], DhcpV4Event::RenewRetry)?;
        self.event_pool.add_timer(t[2], DhcpV4Event::Rebind)?;
        self.event_pool.add_timer(t[3], DhcpV4Event::RebindRetry)?;
        self.event_pool
            .add_timer(lease.lease_time, DhcpV4Event::LeaseExpired)?;
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
        let lease = match recv_dhcp_msg(socket, DhcpV4MessageType::Ack) {
            Ok(l) => l,
            Err(_) => {
                // We should not fail the action but let it retry and timeout
                return Ok(None);
            }
        };
        self.clean_up();
        self.lease = Some(lease.clone());
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
                gen_dhcp_request_delay(self.retry_count),
                DhcpV4Event::DiscoveryTimeout,
            )?;
            if let Some(raw_socket) = &self.raw_socket {
                raw_socket.send(&self.gen_discovery_pkg().to_eth_pkg()?)?;
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
                gen_dhcp_request_delay(self.retry_count),
                DhcpV4Event::RequestTimeout,
            )?;
            if let Some(raw_socket) = &self.raw_socket {
                if let Some(lease) = &self.lease {
                    raw_socket
                        .send(&self.gen_request_pkg(lease).to_eth_pkg()?)?;
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
            gen_dhcp_request_delay(self.retry_count),
            DhcpV4Event::DiscoveryTimeout,
        )?;
        if let Some(raw_socket) = &self.raw_socket {
            raw_socket.send(&self.gen_discovery_pkg().to_eth_pkg()?)?;
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

        let mut dhcp_msg =
            DhcpV4Message::new(&self.config, DhcpV4MessageType::Request);
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
        match recv_dhcp_msg(socket, DhcpV4MessageType::Ack) {
            Ok(lease) => {
                self.clean_up();
                self.lease = Some(lease.clone());
                self.set_renew_rebind_timer(&lease)?;
                Ok(Some(lease))
            }
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
        let mut dhcp_msg =
            DhcpV4Message::new(&self.config, DhcpV4MessageType::Request);
        dhcp_msg.load_lease(lease.clone());
        dhcp_msg.renew_or_rebind(true);
        raw_socket.send(&dhcp_msg.to_eth_pkg()?)?;
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
        match recv_dhcp_msg(socket, DhcpV4MessageType::Ack) {
            Ok(lease) => {
                self.clean_up();
                self.lease = Some(lease.clone());
                self.set_renew_rebind_timer(&lease)?;
                Ok(Some(lease))
            }
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
        self.event_pool
            .add_timer(self.config.timeout, DhcpV4Event::Timeout)?;
        let raw_socket = DhcpRawSocket::new(&self.config)?;
        self.event_pool
            .add_socket(raw_socket.as_raw_fd(), DhcpV4Event::RawPackageIn)?;
        self.event_pool.add_timer(
            gen_dhcp_request_delay(0),
            DhcpV4Event::DiscoveryTimeout,
        )?;
        let dhcp_msg =
            DhcpV4Message::new(&self.config, DhcpV4MessageType::Discovery);
        raw_socket.send(&dhcp_msg.to_eth_pkg()?)?;
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
                _ => todo!(),
            },
            DhcpV4Event::UdpPackageIn => match self.phase {
                DhcpV4Phase::Renew => self.process_renew_recv(),
                _ => todo!(),
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
}

fn recv_dhcp_msg(
    socket: &impl DhcpSocket,
    expected: DhcpV4MessageType,
) -> Result<DhcpV4Lease, DhcpError> {
    let buffer: Vec<u8> = socket.recv()?;
    let reply_dhcp_msg = if socket.is_raw() {
        DhcpV4Message::from_eth_pkg(&buffer)?
    } else {
        DhcpV4Message::from_dhcp_pkg(&buffer)?
    };
    if reply_dhcp_msg.msg_type != expected {
        let e = DhcpError::new(
            ErrorKind::InvalidDhcpServerReply,
            format!(
                "Invalid message type reply from DHCP server, \
                expecting DHCP {}, got {}: debug {:?}",
                expected, reply_dhcp_msg.msg_type, reply_dhcp_msg
            ),
        );
        log::debug!("{}", e);
        return Err(e);
    }
    if let Some(lease) = reply_dhcp_msg.lease {
        Ok(lease)
    } else {
        let e = DhcpError::new(
            ErrorKind::InvalidDhcpServerReply,
            format!(
                "No lease found in the reply from DHCP server: {:?}",
                reply_dhcp_msg
            ),
        );
        log::debug!("{}", e);
        Err(e)
    }
}
