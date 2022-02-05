use std::time::Duration;

use crate::{
    socket::DhcpSocket, time::BootTime, DhcpError, DhcpV4Config, DhcpV4Lease,
    DhcpV4Message, DhcpV4MessageType, ErrorKind,
};

const BROADCAST_MAC_ADDRESS: &str = "ff:ff:ff:ff:ff:ff";
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
    last_renew_time: Option<BootTime>,
    last_rebind_time: Option<BootTime>,
}

impl DhcpV4Client {
    pub fn new(config: DhcpV4Config) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    pub fn request(
        &self,
        lease: Option<DhcpV4Lease>,
    ) -> Result<DhcpV4Lease, DhcpError> {
        let socket = DhcpSocket::new(&self.config)?;
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
        socket: &DhcpSocket,
    ) -> Result<DhcpV4Message, DhcpError> {
        let dhcp_msg =
            DhcpV4Message::new(&self.config, DhcpV4MessageType::Discovery);

        socket.send_raw(BROADCAST_MAC_ADDRESS, &dhcp_msg.to_eth_pkg()?)?;
        let reply_dhcp_msg = socket.recv_dhcpv4_reply()?;
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
        socket: &DhcpSocket,
        lease: DhcpV4Lease,
    ) -> Result<DhcpV4Message, DhcpError> {
        let mut dhcp_msg =
            DhcpV4Message::new(&self.config, DhcpV4MessageType::Request);
        dhcp_msg.load_lease(lease);
        socket.send_raw(BROADCAST_MAC_ADDRESS, &dhcp_msg.to_eth_pkg()?)?;
        let reply_dhcp_msg = socket.recv_dhcpv4_reply()?;
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
        let socket = DhcpSocket::new(&self.config)?;
        socket.send_unicast(
            &lease.yiaddr,
            &lease.siaddr,
            &dhcp_msg.to_dhcp_pkg()?,
        )?;
        let reply_dhcp_msg = socket.recv_dhcpv4_reply()?;
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
        todo!()
    }

    // RFC 2131:
    // In both RENEWING and REBINDING states, if the client receives no response
    // to its DHCPREQUEST message, the client SHOULD wait one-half of the
    // remaining time until T2 (in RENEWING state) and one-half of the remaining
    // lease time (in REBINDING state), down to a minimum of 60 seconds, before
    // retransmitting the DHCPREQUEST message.
    pub fn run(&self, lease: &DhcpV4Lease) -> Result<DhcpV4Lease, DhcpError> {
        let mut lease = lease.clone();
        let mut previous_phase = DhcpV4Phase::PreRenew;
        loop {
            let phase = get_cur_phase(&lease)?;
            log::debug!("Current DHCP pharse {:?}", phase);
            if phase == previous_phase {
                std::thread::sleep(Duration::from_secs(LEASE_CHECK_INTERNAL));
                continue;
            }
            previous_phase = phase;
            match phase {
                DhcpV4Phase::PreRenew => (),
                DhcpV4Phase::Renewing | DhcpV4Phase::Renewing2 => match self
                    .renew(&lease)
                {
                    Ok(l) => {
                        log::debug!("DHCP lease renewed, new lease {:?}", l);
                        lease = l;
                    }
                    Err(e) => {
                        log::debug!("DHCP renew failed, will rebind: {:?}", e);
                    }
                },
                DhcpV4Phase::Rebinding | DhcpV4Phase::Rebinding2 => {
                    match self.rebind(&lease) {
                        Ok(l) => {
                            log::debug!(
                                "DHCP lease rebind done, new lease {:?}",
                                l
                            );
                            lease = l;
                        }
                        Err(_) => {
                            log::error!(
                                "DHCP rebind failed, will fail on lease expire"
                            );
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
    })
}
