use std::os::unix::io::AsRawFd;
use std::time::Duration;

use crate::{
    event::{DhcpEpoll, DhcpV4Event},
    socket::{DhcpRawSocket, DhcpUdpSocket},
    time::{gen_dhcp_request_delay, DhcpTimerFds},
    DhcpError, DhcpV4Config, DhcpV4Lease, DhcpV4Message, DhcpV4MessageType,
    ErrorKind,
};

// We cannot depend on `std::thread::sleep` as the host might be put into
// sleep/hibernate mode.
const LEASE_CHECK_INTERNAL: u64 = 5;

// RFC 2131 suggests four times(60 seconds) retry before fallback to
// discovery phase
const MAX_REQUEST_RETRY_COUNT: u32 = 4;

#[derive(Debug, PartialEq, Clone, Copy)]
enum DhcpV4Phase {
    Discovery,
    Request,
    PreRenew,
    Renew,
    Renew2,
    Rebind,
    Rebind2,
    LeaseTimeout,
}

impl Default for DhcpV4Phase {
    fn default() -> Self {
        Self::Discovery
    }
}

#[derive(Debug, Default)]
pub struct DhcpV4Client {
    config: DhcpV4Config,
    raw_socket: Option<DhcpRawSocket>,
    epoll: DhcpEpoll,
    phase: DhcpV4Phase,
    timer_fds: DhcpTimerFds,
    retry_count: u32,
    lease: Option<DhcpV4Lease>,
}

impl DhcpV4Client {
    pub fn init(
        config: DhcpV4Config,
        lease: Option<DhcpV4Lease>,
    ) -> Result<Self, DhcpError> {
        let epoll = DhcpEpoll::new()?;
        let mut timer_fds = DhcpTimerFds::default();
        timer_fds.add_event(&epoll, DhcpV4Event::Timeout, config.timeout)?;
        let raw_socket = DhcpRawSocket::new(&config)?;
        epoll.add_fd(raw_socket.as_raw_fd(), DhcpV4Event::RawPackageIn)?;

        let (dhcp_msg, phase) = if let Some(lease) = &lease {
            timer_fds.add_event(
                &epoll,
                DhcpV4Event::RequestTimeout,
                gen_dhcp_request_delay(0),
            )?;
            let mut dhcp_msg =
                DhcpV4Message::new(&config, DhcpV4MessageType::Request);
            dhcp_msg.load_lease(lease.clone());
            (dhcp_msg, DhcpV4Phase::Request)
        } else {
            timer_fds.add_event(
                &epoll,
                DhcpV4Event::DiscoveryTimeout,
                gen_dhcp_request_delay(0),
            )?;
            (
                DhcpV4Message::new(&config, DhcpV4MessageType::Discovery),
                DhcpV4Phase::Discovery,
            )
        };
        raw_socket.send(&dhcp_msg.to_eth_pkg()?)?;
        Ok(Self {
            config,
            epoll,
            raw_socket: Some(raw_socket),
            phase,
            timer_fds,
            lease: lease.clone(),
            ..Default::default()
        })
    }

    pub fn poll(
        &self,
        wait_time: isize,
    ) -> Result<Vec<DhcpV4Event>, DhcpError> {
        self.epoll.poll(wait_time)
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
        let lease = self.recv_dhcp_msg(DhcpV4MessageType::Offer)?;
        self.phase = DhcpV4Phase::Request;
        if let Some(raw_socket) = &self.raw_socket {
            raw_socket.send(&self.gen_request_pkg(&lease).to_eth_pkg()?)?;
            // TODO: Handle retry on failure
            Ok(None)
        } else {
            let e = DhcpError::new(ErrorKind::Bug, "No RAW socket".to_string());
            log::error!("{}", e);
            Err(e)
        }
    }

    fn process_request(&mut self) -> Result<Option<DhcpV4Lease>, DhcpError> {
        let lease = self.recv_dhcp_msg(DhcpV4MessageType::Ack)?;
        self.phase = DhcpV4Phase::PreRenew;
        self.lease = Some(lease.clone());
        self.timer_fds
            .del_event(&self.epoll, DhcpV4Event::Timeout)?;
        self.timer_fds
            .del_event(&self.epoll, DhcpV4Event::DiscoveryTimeout)?;
        self.timer_fds
            .del_event(&self.epoll, DhcpV4Event::RequestTimeout)?;
        // TODO:
        // * set timers for renew and rebind
        // * Drop UDP socket
        Ok(Some(lease))
    }

    // RFC 2131 suggests four times(60 seconds) retry before fallback to
    // discovery phase
    fn process_request_timeout(
        &mut self,
    ) -> Result<Option<DhcpV4Lease>, DhcpError> {
        self.timer_fds
            .del_event(&self.epoll, DhcpV4Event::RequestTimeout)?;
        if self.retry_count >= MAX_REQUEST_RETRY_COUNT {
            self.retry_count = 0;
            self.phase = DhcpV4Phase::Discovery;
            self.timer_fds.add_event(
                &self.epoll,
                DhcpV4Event::DiscoveryTimeout,
                gen_dhcp_request_delay(self.retry_count),
            );
            if let Some(raw_socket) = &self.raw_socket {
                raw_socket.send(&self.gen_discovery_pkg().to_eth_pkg()?)?;
                Ok(None)
            } else {
                let e =
                    DhcpError::new(ErrorKind::Bug, "No RAW socket".to_string());
                log::error!("{}", e);
                Err(e)
            }
        } else {
            self.retry_count += 1;
            self.timer_fds.add_event(
                &self.epoll,
                DhcpV4Event::RequestTimeout,
                gen_dhcp_request_delay(self.retry_count),
            );
            if let Some(raw_socket) = &self.raw_socket {
                if let Some(lease) = &self.lease {
                    raw_socket
                        .send(&self.gen_request_pkg(lease).to_eth_pkg()?)?;
                    Ok(None)
                } else {
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
        self.timer_fds
            .del_event(&self.epoll, DhcpV4Event::RequestTimeout)?;
        self.retry_count += 1;
        self.timer_fds.add_event(
            &self.epoll,
            DhcpV4Event::DiscoveryTimeout,
            gen_dhcp_request_delay(self.retry_count),
        );
        if let Some(raw_socket) = &self.raw_socket {
            raw_socket.send(&self.gen_discovery_pkg().to_eth_pkg()?)?;
            Ok(None)
        } else {
            let e = DhcpError::new(ErrorKind::Bug, "No RAW socket".to_string());
            log::error!("{}", e);
            Err(e)
        }
    }

    fn process_timeout(&mut self) -> Result<Option<DhcpV4Lease>, DhcpError> {
        self.timer_fds = DhcpTimerFds::default();
        let e = DhcpError::new(ErrorKind::Timeout, "Timeout".to_string());
        log::error!("{}", e);
        Err(e)
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
                _ => todo!(),
            },
            DhcpV4Event::RequestTimeout => self.process_request_timeout(),
            DhcpV4Event::DiscoveryTimeout => self.process_discovery_timeout(),
            DhcpV4Event::Timeout => self.process_timeout(),
            _ => todo!(),
        }
    }

    fn recv_dhcp_msg(
        &self,
        expected: DhcpV4MessageType,
    ) -> Result<DhcpV4Lease, DhcpError> {
        let socket = if let Some(s) = &self.raw_socket {
            s
        } else {
            let e = DhcpError::new(ErrorKind::Bug, "No RAW socket".to_string());
            log::error!("{}", e);
            return Err(e);
        };
        let buffer: Vec<u8> = socket.recv()?;
        let reply_dhcp_msg = DhcpV4Message::from_eth_pkg(&buffer)?;
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
            return Err(e);
        }
    }

    /*

    fn dhcp_discovery(
        &self,
        socket: &DhcpRawSocket,
    ) -> Result<DhcpV4Message, DhcpError> {
        let dhcp_msg =
            DhcpV4Message::new(&self.config, DhcpV4MessageType::Discovery);

        let buffer = socket.send_recv(&dhcp_msg.to_eth_pkg()?)?;
        let reply_dhcp_msg = DhcpV4Message::from_eth_pkg(&buffer)?;
        if reply_dhcp_msg.msg_type != DhcpV4MessageType::Offer {
            let e = DhcpError::new(
                ErrorKind::InvalidDhcpServerReply,
                format!(
                    "Invalid message type reply from DHCP server, \
                    expecting DHCP offer, got {}: debug {:?}",
                    reply_dhcp_msg.msg_type, reply_dhcp_msg
                ),
            );
            log::debug!("{}", e);
            return Err(e);
        }
        Ok(reply_dhcp_msg)
    }

    fn dhcp_request(
        &self,
        socket: &DhcpRawSocket,
        lease: DhcpV4Lease,
    ) -> Result<DhcpV4Message, DhcpError> {
        let mut dhcp_msg =
            DhcpV4Message::new(&self.config, DhcpV4MessageType::Request);
        dhcp_msg.load_lease(lease);
        let buffer = socket.send_recv(&dhcp_msg.to_eth_pkg()?)?;
        let reply_dhcp_msg = DhcpV4Message::from_eth_pkg(&buffer)?;
        if reply_dhcp_msg.msg_type != DhcpV4MessageType::Ack {
            let e = DhcpError::new(
                ErrorKind::InvalidDhcpServerReply,
                format!(
                    "Invalid message type reply from DHCP server, \
                    expecting DHCP ack, got {}: debug {:?}",
                    reply_dhcp_msg.msg_type, reply_dhcp_msg
                ),
            );
            log::debug!("{}", e);
            return Err(e);
        }
        Ok(reply_dhcp_msg)
    }

    // Unicast to DHCP server requesting lease extension, with ciaddr field
    // and empty server identifier.
    // TODO: The `xid` should be matching.
    fn renew(&self, lease: &DhcpV4Lease) -> Result<DhcpV4Lease, DhcpError> {
        let mut dhcp_msg =
            DhcpV4Message::new(&self.config, DhcpV4MessageType::Request);
        dhcp_msg.load_lease(lease.clone());
        dhcp_msg.renew_or_rebind(true);
        let buffer = DhcpUdpSocket::send_recv(
            self.config.iface_name.as_str(),
            &lease.yiaddr,
            &lease.siaddr,
            &dhcp_msg.to_dhcp_pkg()?,
            self.config.socket_timeout,
        )?;
        let reply_dhcp_msg = DhcpV4Message::from_dhcp_pkg(buffer.as_slice())?;
        log::debug!("Got DHCP message reply: {:?}", reply_dhcp_msg);
        if reply_dhcp_msg.msg_type != DhcpV4MessageType::Ack {
            let e = DhcpError::new(
                ErrorKind::InvalidDhcpServerReply,
                format!(
                    "Invalid message type reply from DHCP server, \
                    expecting DHCP ack, got {}: debug {:?}",
                    reply_dhcp_msg.msg_type, reply_dhcp_msg
                ),
            );
            log::debug!("{}", e);
            return Err(e);
        }
        reply_dhcp_msg.lease.ok_or_else(|| {
            let e = DhcpError::new(
                ErrorKind::NoLease,
                "DHCP server provide no lease reply".to_string(),
            );
            log::debug!("{}", e);
            e
        })
    }

    // Broadcast to all DHCP servers requesting lease extension with ciaddr.
    fn rebind(&self, lease: &DhcpV4Lease) -> Result<DhcpV4Lease, DhcpError> {
        let mut dhcp_msg =
            DhcpV4Message::new(&self.config, DhcpV4MessageType::Request);
        dhcp_msg.load_lease(lease.clone());
        dhcp_msg.renew_or_rebind(true);
        let socket = DhcpRawSocket::new(&self.config)?;
        let buffer = socket.send_recv(&dhcp_msg.to_eth_pkg()?)?;
        let reply_dhcp_msg = DhcpV4Message::from_eth_pkg(&buffer)?;
        if reply_dhcp_msg.msg_type != DhcpV4MessageType::Ack {
            let e = DhcpError::new(
                ErrorKind::InvalidDhcpServerReply,
                format!(
                    "Invalid message type reply from DHCP server, \
                    expecting DHCP ack, got {}: debug {:?}",
                    reply_dhcp_msg.msg_type, reply_dhcp_msg
                ),
            );
            log::debug!("{}", e);
            return Err(e);
        }
        reply_dhcp_msg.lease.ok_or_else(|| {
            let e = DhcpError::new(
                ErrorKind::NoLease,
                "DHCP server provide no lease reply".to_string(),
            );
            log::debug!("{}", e);
            e
        })
    }

    // RFC 2131:
    // In both RENEWING and REBINDING states, if the client receives no response
    // to its DHCPREQUEST message, the client SHOULD wait one-half of the
    // remaining time until T2 (in RENEWING state) and one-half of the remaining
    // lease time (in REBINDING state), down to a minimum of 60 seconds, before
    // retransmitting the DHCPREQUEST message.
    pub fn run(
        &mut self,
        lease: &DhcpV4Lease,
    ) -> Result<DhcpV4Lease, DhcpError> {
        let mut previous_phase = DhcpV4Phase::PreRenew;
        loop {
            let phase = get_cur_phase(lease)?;
            log::debug!("Current DHCP phase {:?}", phase);
            if phase == previous_phase {
                std::thread::sleep(Duration::from_secs(LEASE_CHECK_INTERNAL));
                continue;
            }
            previous_phase = phase;
            match phase {
                DhcpV4Phase::PreRenew => (),
                DhcpV4Phase::Renew => {
                    if !self.renew_failed {
                        match self.renew(lease) {
                            Ok(l) => {
                                log::debug!(
                                    "DHCP lease renewed, new lease {:?}",
                                    l
                                );
                                self.renew_failed = false;
                                self.renew2_failed = false;
                                self.rebind_failed = false;
                                self.rebind2_failed = false;
                                return Ok(l);
                            }
                            Err(e) => {
                                log::warn!(
                                    "DHCP renew failed, will retry: {:?}",
                                    e
                                );
                                self.renew_failed = true;
                            }
                        }
                    }
                }
                DhcpV4Phase::Renew2 => {
                    if !self.renew2_failed {
                        match self.renew(lease) {
                            Ok(l) => {
                                log::debug!(
                                    "DHCP lease renewed, new lease {:?}",
                                    l
                                );
                                self.renew_failed = false;
                                self.renew2_failed = false;
                                self.rebind_failed = false;
                                self.rebind2_failed = false;
                                return Ok(l);
                            }
                            Err(e) => {
                                log::warn!(
                                    "DHCP second renew failed, will rebind: \
                                    {:?}",
                                    e
                                );
                                self.renew2_failed = true;
                            }
                        }
                    }
                }
                DhcpV4Phase::Rebind => {
                    if !self.rebind_failed {
                        match self.rebind(lease) {
                            Ok(l) => {
                                log::debug!(
                                    "DHCP lease rebind done, new lease {:?}",
                                    l
                                );
                                self.renew_failed = false;
                                self.renew2_failed = false;
                                self.rebind_failed = false;
                                self.rebind2_failed = false;
                                return Ok(l);
                            }
                            Err(_) => {
                                log::warn!("DHCP rebind failed, will retry");
                                self.rebind_failed = true;
                            }
                        }
                    }
                }
                DhcpV4Phase::Rebind2 => {
                    if !self.rebind2_failed {
                        match self.rebind(lease) {
                            Ok(l) => {
                                log::debug!(
                                    "DHCP lease rebind done, new lease {:?}",
                                    l
                                );
                                self.renew_failed = false;
                                self.renew2_failed = false;
                                self.rebind_failed = false;
                                self.rebind2_failed = false;
                                return Ok(l);
                            }
                            Err(_) => {
                                log::error!(
                                    "DHCP rebind second call failed, \
                                    will fail on lease expire"
                                );
                                self.rebind2_failed = true;
                            }
                        }
                    }
                }
                DhcpV4Phase::LeaseTimeout => {
                    let e = DhcpError::new(
                        ErrorKind::NoLease,
                        format!(
                            "Failed to renew and rebind the DHCP lease {}, \
                            please run do request again",
                            &lease.yiaddr
                        ),
                    );
                    log::error!("{}", e);
                    return Err(e);
                }
                _ => todo!(),
            };
            std::thread::sleep(Duration::from_secs(LEASE_CHECK_INTERNAL));
        }
    }
    */
}

/*
fn get_cur_phase(lease: &DhcpV4Lease) -> Result<DhcpV4Phase, DhcpError> {
    let elapsed = lease.got_time.elapsed()?.as_secs();
    let lease_time = lease.lease_time as u64;
    let t2 = lease.t2 as u64;
    let t1 = lease.t1 as u64;
    Ok(if elapsed > lease_time {
        DhcpV4Phase::LeaseTimeout
    } else if elapsed > t2 + (lease_time - t2) / 2 {
        DhcpV4Phase::Rebind2
    } else if elapsed > t2 {
        DhcpV4Phase::Rebind
    } else if elapsed > t1 + (t2 - t1) / 2 {
        DhcpV4Phase::Renew2
    } else if elapsed > t1 {
        DhcpV4Phase::Renew
    } else {
        DhcpV4Phase::PreRenew
        //        DhcpV4Phase::Renewing
    })
}
*/
