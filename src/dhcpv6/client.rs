// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv6Addr;
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use rand::Rng;

use super::{
    msg::{DhcpV6Message, DhcpV6MessageType},
    time::{
        gen_rebind_wait_time, gen_renew_wait_time, gen_request_wait_time,
        gen_solicit_wait_time,
    },
};
use crate::{
    event::DhcpEventPool,
    socket::{DhcpSocket, DhcpUdpSocket},
    DhcpError, DhcpV6Config, DhcpV6Event, DhcpV6IaType, DhcpV6Lease, ErrorKind,
};

const DHCPV6_REPLAY_AND_SRVS: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

#[derive(Debug, PartialEq, Clone, Copy)]
enum DhcpV6Phase {
    Done,
    PreSolicit,
    Solicit,
    PreRequest,
    Request,
    Renew,
    Rebind,
}

impl std::fmt::Display for DhcpV6Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Done => "done",
                Self::PreSolicit => "pre_solicit",
                Self::PreRequest => "pre_request",
                Self::Solicit => "solicit",
                Self::Request => "request",
                Self::Renew => "renew",
                Self::Rebind => "rebind",
            }
        )
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct DhcpV6Client {
    config: DhcpV6Config,
    event_pool: DhcpEventPool<DhcpV6Event>,
    lease: Option<DhcpV6Lease>,
    phase: DhcpV6Phase,
    udp_socket: Option<DhcpUdpSocket>,
    xid: [u8; 3],
    retrans_timeout: Duration,
    retrans_count: u32,
    trans_begin_time: Option<Instant>,
    trans_dhcp_msg: Option<DhcpV6Message>,
}

impl AsRawFd for DhcpV6Client {
    fn as_raw_fd(&self) -> RawFd {
        self.event_pool.epoll.as_raw_fd()
    }
}

impl DhcpV6Client {
    fn clean_up(&mut self) {
        self.lease = None;
        self.retrans_count = 0;
        self.phase = DhcpV6Phase::Done;
        self.event_pool.remove_all_event();
        self.udp_socket = None;
    }

    pub fn init(
        mut config: DhcpV6Config,
        lease: Option<DhcpV6Lease>,
    ) -> Result<Self, DhcpError> {
        config.init()?;
        let mut event_pool = DhcpEventPool::new()?;
        event_pool.add_timer(
            Duration::from_secs(config.timeout.into()),
            DhcpV6Event::Timeout,
        )?;

        // In RFC 8415, the `transaction-id` is a 3-octet field
        let mut xid: [u8; 3] = [0; 3];
        xid.copy_from_slice(
            &rand::thread_rng().gen::<u32>().to_le_bytes()[..3],
        );
        let mut ret = Self {
            config,
            event_pool,
            lease,
            phase: DhcpV6Phase::Done,
            xid,
            udp_socket: None,
            retrans_timeout: Duration::new(0, 0),
            retrans_count: 0,
            trans_begin_time: None,
            trans_dhcp_msg: None,
        };
        if ret.lease.is_some() {
            ret.process_renew()?;
        } else {
            ret.process_solicit()?;
        }

        Ok(ret)
    }

    fn clean_trans_counters(&mut self) {
        self.trans_dhcp_msg = None;
        self.retrans_count = 0;
        self.retrans_timeout = Duration::new(0, 0);
        self.trans_begin_time = None;
    }

    pub fn poll(&self, wait_time: u32) -> Result<Vec<DhcpV6Event>, DhcpError> {
        self.event_pool.poll(wait_time)
    }

    pub fn process(
        &mut self,
        event: DhcpV6Event,
    ) -> Result<Option<DhcpV6Lease>, DhcpError> {
        log::debug!("Processing event {:?}", event);
        match event {
            DhcpV6Event::TransmitWait => {
                self.process_transmit()?;
                Ok(None)
            }
            DhcpV6Event::UdpPackageIn => match self.phase {
                DhcpV6Phase::Solicit => {
                    self.process_advertise()?;
                    Ok(None)
                }
                DhcpV6Phase::Request
                | DhcpV6Phase::Renew
                | DhcpV6Phase::Rebind => self.process_reply(),
                _ => Err(DhcpError::new(
                    ErrorKind::Bug,
                    format!(
                        "Cannot process unsupported phase {} in \
                        UdpPackageIn",
                        self.phase
                    ),
                )),
            },
            DhcpV6Event::Renew => {
                self.process_renew()?;
                Ok(None)
            }
            DhcpV6Event::LeaseExpired => {
                self.process_solicit()?;
                Ok(None)
            }
            DhcpV6Event::Rebind => {
                self.process_rebind()?;
                Ok(None)
            }
            _ => Err(DhcpError::new(
                ErrorKind::Bug,
                format!("Cannot process unsupported event {}", event),
            )),
        }
    }

    /// The RFC 8415:
    ///     Implementations SHOULD retransmit one or more times but MAY choose
    ///     to terminate the retransmission procedure early.
    /// So here we decided not to wait reply from DHCPv6 server.
    /// To request new release, you need to create new instance of
    /// [DhcpV6Client].
    pub fn release(&mut self, lease: &DhcpV6Lease) -> Result<(), DhcpError> {
        if self.udp_socket.is_none() {
            let socket = DhcpUdpSocket::new_v6(
                self.config.iface_index,
                &self.config.src_ip,
                self.config.socket_timeout,
            )?;
            self.udp_socket = Some(socket);
        }
        let socket = self.udp_socket.as_ref().unwrap();

        let mut dhcp_msg = DhcpV6Message::new(
            &self.config,
            DhcpV6MessageType::RELEASE,
            self.xid,
        );
        dhcp_msg.load_lease(lease.clone())?;
        let dst = if lease.srv_ip.is_unspecified() {
            &DHCPV6_REPLAY_AND_SRVS
        } else {
            &lease.srv_ip
        };
        socket.send_to_v6(dst, &dhcp_msg.to_dhcp_pkg()?)?;

        self.clean_up();
        Ok(())
    }

    fn process_solicit(&mut self) -> Result<(), DhcpError> {
        self.phase = DhcpV6Phase::PreSolicit;
        self.lease = None;
        self.retrans_timeout =
            gen_solicit_wait_time(Instant::now(), 0, Duration::new(0, 0))?;
        self.trans_dhcp_msg = Some(DhcpV6Message::new(
            &self.config,
            DhcpV6MessageType::SOLICIT,
            self.xid,
        ));
        self.event_pool
            .add_timer(self.retrans_timeout, DhcpV6Event::TransmitWait)
    }

    fn process_advertise(&mut self) -> Result<(), DhcpError> {
        self.event_pool.del_timer(DhcpV6Event::Timeout)?;
        let socket = match self.udp_socket.as_ref() {
            Some(s) => s,
            None => {
                return Err(DhcpError::new(
                    ErrorKind::Bug,
                    format!("Got NULL socket for process_solicit {:?}", self),
                ));
            }
        };
        let lease = match recv_dhcp_msg(
            socket,
            DhcpV6MessageType::ADVERTISE,
            self.xid,
        )? {
            Some(l) => l,
            None => return Ok(()),
        };

        let mut dhcp_msg = DhcpV6Message::new(
            &self.config,
            DhcpV6MessageType::REQUEST,
            self.xid,
        );
        if let Err(e) = dhcp_msg.load_lease(lease.clone()) {
            log::warn!("Invalid DHCPv6 lease: {e}, will retry later");
            return Ok(());
        }
        self.event_pool.del_timer(DhcpV6Event::TransmitWait)?;
        self.clean_trans_counters();
        self.retrans_timeout =
            gen_request_wait_time(Instant::now(), 0, Duration::new(0, 0))?;
        self.trans_dhcp_msg = Some(dhcp_msg);
        self.event_pool
            .add_timer(self.retrans_timeout, DhcpV6Event::TransmitWait)?;
        self.phase = DhcpV6Phase::PreRequest;
        Ok(())
    }

    // TODO: Handle sever reply with valid_life with 0(indicate requested
    //       IA is invalid)
    fn process_reply(&mut self) -> Result<Option<DhcpV6Lease>, DhcpError> {
        let socket = match self.udp_socket.as_ref() {
            Some(s) => s,
            None => {
                return Err(DhcpError::new(
                    ErrorKind::Bug,
                    format!("Got NULL socket for process_solicit {:?}", self),
                ));
            }
        };
        let lease =
            match recv_dhcp_msg(socket, DhcpV6MessageType::REPLY, self.xid)? {
                Some(l) => l,
                None => return Ok(None),
            };

        self.phase = DhcpV6Phase::Done;
        self.event_pool.del_socket(DhcpV6Event::UdpPackageIn)?;
        self.udp_socket = None;
        self.event_pool.del_timer(DhcpV6Event::TransmitWait)?;
        self.lease = Some(lease.clone());
        self.clean_trans_counters();
        self.schedule_renew_rebind_restart()?;

        Ok(Some(lease))
    }

    // TODO: rate control
    fn process_transmit(&mut self) -> Result<(), DhcpError> {
        self.event_pool.del_timer(DhcpV6Event::TransmitWait)?;
        self.schedule_next_retransmit()?;

        // The RFC 8415 said
        //      A client is not expected to listen for a response during the
        //      entire RT period and may turn off listening capabilities after
        //      waiting at least the shorter of RT and MAX_WAIT_TIME due to
        //      power consumption saving or other reasons.  Of course, a client
        //      MUST listen for a Reconfigure if it has negotiated for its use
        //      with the server.
        // Hence it is OK to create UDP socket when actual transmitting happens.
        if self.udp_socket.is_none() {
            let socket = DhcpUdpSocket::new_v6(
                self.config.iface_index,
                &self.config.src_ip,
                self.config.socket_timeout,
            )?;
            self.event_pool
                .add_socket(socket.as_raw_fd(), DhcpV6Event::UdpPackageIn)?;
            self.udp_socket = Some(socket);
        }
        let socket = self.udp_socket.as_ref().unwrap();
        let dhcp_msg = match self.trans_dhcp_msg.as_mut() {
            Some(p) => p,
            None => {
                return Err(DhcpError::new(
                    ErrorKind::Bug,
                    format!(
                        "Got NULL DHCP package for process_transmit {:?}",
                        self
                    ),
                ));
            }
        };
        if self.retrans_count > 1 {
            // We are safe to use unwrap as `schedule_next_retransmit()`
            // already confirmed so.
            dhcp_msg.add_elapsed_time(self.trans_begin_time.unwrap());
        }
        // TODO Support unicast to server
        socket.send_to_v6(&DHCPV6_REPLAY_AND_SRVS, &dhcp_msg.to_dhcp_pkg()?)?;
        match self.phase {
            DhcpV6Phase::PreSolicit => self.phase = DhcpV6Phase::Solicit,
            DhcpV6Phase::PreRequest => self.phase = DhcpV6Phase::Request,
            _ => (),
        }
        Ok(())
    }

    fn schedule_next_retransmit(&mut self) -> Result<(), DhcpError> {
        self.retrans_count += 1;
        if self.trans_begin_time.is_none() {
            self.trans_begin_time = Some(Instant::now());
        }
        self.retrans_timeout = match self.phase {
            DhcpV6Phase::PreSolicit | DhcpV6Phase::Solicit => {
                gen_solicit_wait_time(
                    self.trans_begin_time.unwrap(),
                    self.retrans_count,
                    self.retrans_timeout,
                )?
            }
            DhcpV6Phase::PreRequest | DhcpV6Phase::Request => {
                gen_request_wait_time(
                    self.trans_begin_time.unwrap(),
                    self.retrans_count,
                    self.retrans_timeout,
                )?
            }
            DhcpV6Phase::Renew => {
                if let Some(lease) = self.lease.as_ref() {
                    gen_rebind_wait_time(
                        self.trans_begin_time.unwrap(),
                        self.retrans_count,
                        self.retrans_timeout,
                        Duration::from_secs(lease.t2.into()),
                    )?
                } else {
                    return Err(DhcpError::new(
                        ErrorKind::Bug,
                        format!(
                            "Got NULL lease for DhcpV6Phase::Rebind in \
                            schedule_next_retransmit(): {:?}",
                            self
                        ),
                    ));
                }
            }
            DhcpV6Phase::Rebind => {
                if let Some(lease) = self.lease.as_ref() {
                    gen_rebind_wait_time(
                        self.trans_begin_time.unwrap(),
                        self.retrans_count,
                        self.retrans_timeout,
                        Duration::from_secs(lease.valid_life.into()),
                    )?
                } else {
                    return Err(DhcpError::new(
                        ErrorKind::Bug,
                        format!(
                            "Got NULL lease for DhcpV6Phase::Rebind in \
                            schedule_next_retransmit(): {:?}",
                            self
                        ),
                    ));
                }
            }
            _ => {
                return Err(DhcpError::new(
                    ErrorKind::Bug,
                    format!(
                        "Got invalid phase {:?} for \
                        `schedule_next_retransmit()`: {:?}",
                        self.phase, self
                    ),
                ));
            }
        };
        self.event_pool
            .add_timer(self.retrans_timeout, DhcpV6Event::TransmitWait)
    }

    fn schedule_renew_rebind_restart(&mut self) -> Result<(), DhcpError> {
        if let Some(lease) = self.lease.as_ref() {
            self.event_pool.add_timer(
                Duration::from_secs(lease.valid_life.into()),
                DhcpV6Event::LeaseExpired,
            )?;
            if lease.ia_type != DhcpV6IaType::TemporaryAddresses {
                self.event_pool.add_timer(
                    Duration::from_secs(lease.t1.into()),
                    DhcpV6Event::Renew,
                )?;
                self.event_pool.add_timer(
                    Duration::from_secs(lease.t2.into()),
                    DhcpV6Event::Rebind,
                )?;
            }
            Ok(())
        } else {
            Err(DhcpError::new(
                ErrorKind::Bug,
                format!(
                    "Got NULL lease for `schedule_renew_rebind()`: {:?}",
                    self
                ),
            ))
        }
    }

    fn process_renew(&mut self) -> Result<(), DhcpError> {
        self.event_pool.del_timer(DhcpV6Event::Renew)?;
        self.phase = DhcpV6Phase::Renew;
        if let Some(lease) = self.lease.as_ref() {
            self.retrans_timeout = gen_renew_wait_time(
                Instant::now(),
                0,
                Duration::new(0, 0),
                Duration::from_secs(lease.t2.into()),
            )?;
            let mut dhcp_msg = DhcpV6Message::new(
                &self.config,
                DhcpV6MessageType::RENEW,
                self.xid,
            );
            dhcp_msg.load_lease(lease.clone())?;
            self.trans_dhcp_msg = Some(dhcp_msg);
            self.event_pool
                .add_timer(self.retrans_timeout, DhcpV6Event::TransmitWait)
        } else {
            Err(DhcpError::new(
                ErrorKind::Bug,
                format!("Got NULL lease for `process_renew()`: {:?}", self),
            ))
        }
    }

    fn process_rebind(&mut self) -> Result<(), DhcpError> {
        self.event_pool.del_timer(DhcpV6Event::Rebind)?;
        self.phase = DhcpV6Phase::Rebind;
        if let Some(lease) = self.lease.as_ref() {
            self.retrans_timeout = gen_rebind_wait_time(
                Instant::now(),
                0,
                Duration::new(0, 0),
                Duration::from_secs(lease.valid_life.into()),
            )?;
            let mut dhcp_msg = DhcpV6Message::new(
                &self.config,
                DhcpV6MessageType::REBIND,
                self.xid,
            );
            dhcp_msg.load_lease(lease.clone())?;
            self.trans_dhcp_msg = Some(dhcp_msg);
            self.event_pool
                .add_timer(self.retrans_timeout, DhcpV6Event::TransmitWait)
        } else {
            Err(DhcpError::new(
                ErrorKind::Bug,
                format!("Got NULL lease for `process_renew()`: {:?}", self),
            ))
        }
    }
}

fn recv_dhcp_msg(
    socket: &DhcpUdpSocket,
    expected: DhcpV6MessageType,
    xid: [u8; 3],
) -> Result<Option<DhcpV6Lease>, DhcpError> {
    let buffer: Vec<u8> = socket.recv()?;
    let reply_dhcp_msg = DhcpV6Message::from_dhcp_pkg(&buffer)?;
    if reply_dhcp_msg.xid != xid {
        log::debug!(
            "Dropping DHCP message due to xid miss-match. \
            Expecting {:?}, got {:?}",
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
