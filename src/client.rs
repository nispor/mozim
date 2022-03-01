use std::time::Duration;

use crate::{
    socket::{DhcpRawSocket, DhcpUdpSocket},
    time::gen_dhcp_request_delay,
    DhcpError, DhcpV4Config, DhcpV4Lease, DhcpV4Message, DhcpV4MessageType,
    ErrorKind,
};

// We cannot depend on `std::thread::sleep` as the host might be put into
// sleep/hibernate mode.
const LEASE_CHECK_INTERNAL: u64 = 5;

#[derive(Debug, PartialEq, Clone, Copy)]
enum DhcpV4Phase {
    PreRenew,
    Renewing,
    Renewing2,
    Rebinding,
    Rebinding2,
    LeaseTimeout,
}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct DhcpV4Client {
    config: DhcpV4Config,
    // We store these information to ensure we does not do more than twice
    // renew or rebind per RFC 2131 even when user run `DhcpV4Client::run()`
    // multiple times
    renew_failed: bool,
    renew2_failed: bool,
    rebind_failed: bool,
    rebind2_failed: bool,
}

impl DhcpV4Client {
    pub fn new(config: DhcpV4Config) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    // RFC 2131, section 4.1 "Constructing and sending DHCP messages" has
    // retransmission guideline.
    pub fn request(
        &self,
        lease: Option<&DhcpV4Lease>,
        max_retry: u32,
    ) -> Result<DhcpV4Lease, DhcpError> {
        let mut retry_count: u32 = 0;
        loop {
            match self._request(lease.cloned()) {
                Ok(l) => {
                    return Ok(l);
                }
                Err(e) => {
                    if retry_count >= max_retry {
                        return Err(e);
                    } else {
                        let delay = gen_dhcp_request_delay(retry_count);
                        log::warn!(
                            "DHCP request failed will retry in {}.{} seconds",
                            delay.as_secs(),
                            delay.as_millis() / 1000,
                        );
                        std::thread::sleep(delay);
                        retry_count += 1;
                    }
                }
            }
        }
    }

    fn _request(
        &self,
        lease: Option<DhcpV4Lease>,
    ) -> Result<DhcpV4Lease, DhcpError> {
        let socket = DhcpRawSocket::new(&self.config)?;
        let ack_dhcp_msg = if let Some(lease) = lease {
            self.dhcp_request(&socket, lease)?
        } else {
            let offer_msg = self.dhcp_discovery(&socket)?;
            self.dhcp_request(
                &socket,
                offer_msg.lease.ok_or_else(|| {
                    let e = DhcpError::new(
                        ErrorKind::InvalidDhcpServerReply,
                        "No lease reply from DHCP server".to_string(),
                    );
                    log::debug!("{}", e);
                    e
                })?,
            )?
        };
        ack_dhcp_msg.lease.ok_or_else(|| {
            let e = DhcpError::new(
                ErrorKind::NoLease,
                "DHCP server provide no lease reply".to_string(),
            );
            log::debug!("{}", e);
            e
        })
    }

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
                DhcpV4Phase::Renewing => {
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
                DhcpV4Phase::Renewing2 => {
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
                DhcpV4Phase::Rebinding => {
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
                DhcpV4Phase::Rebinding2 => {
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
            };
            std::thread::sleep(Duration::from_secs(LEASE_CHECK_INTERNAL));
        }
    }
}

fn get_cur_phase(lease: &DhcpV4Lease) -> Result<DhcpV4Phase, DhcpError> {
    let elapsed = lease.got_time.elapsed()?.as_secs();
    let lease_time = lease.lease_time as u64;
    let t2 = lease.t2 as u64;
    let t1 = lease.t1 as u64;
    Ok(if elapsed > lease_time {
        DhcpV4Phase::LeaseTimeout
    } else if elapsed > t2 + (lease_time - t2) / 2 {
        DhcpV4Phase::Rebinding2
    } else if elapsed > t2 {
        DhcpV4Phase::Rebinding
    } else if elapsed > t1 + (t2 - t1) / 2 {
        DhcpV4Phase::Renewing2
    } else if elapsed > t1 {
        DhcpV4Phase::Renewing
    } else {
        DhcpV4Phase::PreRenew
        //        DhcpV4Phase::Renewing
    })
}
