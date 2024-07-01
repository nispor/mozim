// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv4Addr;

use dhcproto::{v4, Decodable, Decoder, Encodable};

use crate::{
    mac::{
        mac_address_to_eth_mac_bytes, mac_str_to_u8_array,
        BROADCAST_MAC_ADDRESS,
    },
    DhcpError, DhcpV4Config, DhcpV4Lease, ErrorKind,
};

const DEFAULT_TTL: u8 = 128;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DhcpV4MessageType {
    Discovery,
    Offer,
    Request,
    Ack,
    Nack,
    Decline,
    Release,
    Inform,
    Unknown,
}

impl Default for DhcpV4MessageType {
    fn default() -> Self {
        Self::Unknown
    }
}

impl std::fmt::Display for DhcpV4MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}",
            match self {
                Self::Discovery => "discovery",
                Self::Offer => "offer",
                Self::Request => "request",
                Self::Ack => "ack",
                Self::Nack => "nack",
                Self::Decline => "decline",
                Self::Release => "release",
                Self::Inform => "inform",
                Self::Unknown => "unknown",
            }
        )
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct DhcpV4Message {
    pub msg_type: DhcpV4MessageType,
    pub lease: Option<DhcpV4Lease>,
    pub config: DhcpV4Config,
    renew_or_rebind: bool,
    pub(crate) xid: u32,
}

impl DhcpV4Message {
    pub fn new(
        config: &DhcpV4Config,
        msg_type: DhcpV4MessageType,
        xid: u32,
    ) -> Self {
        Self {
            msg_type,
            config: config.clone(),
            lease: None,
            renew_or_rebind: false,
            xid,
        }
    }

    pub fn load_lease(&mut self, lease: DhcpV4Lease) -> &mut Self {
        self.lease = Some(lease);
        self
    }

    pub(crate) fn renew_or_rebind(&mut self, value: bool) -> &mut Self {
        self.renew_or_rebind = value;
        self
    }

    pub(crate) fn to_dhcp_pkg(&self) -> Result<Vec<u8>, DhcpError> {
        let mut dhcp_msg = v4::Message::default();
        dhcp_msg.set_flags(v4::Flags::default());
        dhcp_msg.set_xid(self.xid);

        if !self.config.host_name.is_empty() {
            dhcp_msg.set_sname_str(self.config.host_name.clone());
        }

        if !self.config.src_mac.is_empty() {
            dhcp_msg
                .set_chaddr(&mac_str_to_u8_array(self.config.src_mac.as_str()));
        }

        if self.msg_type == DhcpV4MessageType::Discovery {
            dhcp_msg
                .opts_mut()
                .insert(v4::DhcpOption::MessageType(v4::MessageType::Discover));
            dhcp_msg
                .opts_mut()
                .insert(v4::DhcpOption::ParameterRequestList(vec![
                    v4::OptionCode::Hostname,
                    v4::OptionCode::SubnetMask,
                    v4::OptionCode::Router,
                    v4::OptionCode::DomainNameServer,
                    v4::OptionCode::DomainName,
                    v4::OptionCode::InterfaceMtu,
                    v4::OptionCode::NTPServers,
                ]));
        } else if self.msg_type == DhcpV4MessageType::Request {
            dhcp_msg
                .opts_mut()
                .insert(v4::DhcpOption::MessageType(v4::MessageType::Request));
            if let Some(lease) = self.lease.as_ref() {
                if self.renew_or_rebind {
                    dhcp_msg.set_ciaddr(lease.yiaddr);
                } else {
                    if lease.srv_id != Ipv4Addr::new(0, 0, 0, 0) {
                        dhcp_msg.opts_mut().insert(
                            v4::DhcpOption::ServerIdentifier(lease.srv_id),
                        );
                    } else {
                        dhcp_msg.opts_mut().insert(
                            v4::DhcpOption::ServerIdentifier(lease.siaddr),
                        );
                    }
                    dhcp_msg.opts_mut().insert(
                        v4::DhcpOption::RequestedIpAddress(lease.yiaddr),
                    );
                }
            } else {
                let e = DhcpError::new(
                    ErrorKind::InvalidArgument,
                    "No DHCP lease found for DHCP request, \
                    please run DhcpV4Message::load_lease() first"
                        .to_string(),
                );
                log::error!("{}", e);
                return Err(e);
            }
            dhcp_msg
                .opts_mut()
                .insert(v4::DhcpOption::ParameterRequestList(vec![
                    v4::OptionCode::Hostname,
                    v4::OptionCode::SubnetMask,
                    v4::OptionCode::Router,
                    v4::OptionCode::DomainNameServer,
                    v4::OptionCode::DomainName,
                    v4::OptionCode::InterfaceMtu,
                    v4::OptionCode::NTPServers,
                ]));
        } else if self.msg_type == DhcpV4MessageType::Release {
            if let Some(lease) = self.lease.as_ref() {
                dhcp_msg.set_ciaddr(lease.yiaddr);
                dhcp_msg.opts_mut().insert(v4::DhcpOption::MessageType(
                    v4::MessageType::Release,
                ));
                if lease.srv_id != Ipv4Addr::new(0, 0, 0, 0) {
                    dhcp_msg
                        .opts_mut()
                        .insert(v4::DhcpOption::ServerIdentifier(lease.srv_id));
                } else {
                    dhcp_msg
                        .opts_mut()
                        .insert(v4::DhcpOption::ServerIdentifier(lease.siaddr));
                }
            } else {
                return Err(DhcpError::new(
                    ErrorKind::Bug,
                    format!("Got no lease for RELEASE message: {self:?}"),
                ));
            }
        } else {
            let e = DhcpError::new(
                ErrorKind::InvalidArgument,
                format!("Unsupported DHCP message type {:?}", self.msg_type),
            );
            log::error!("{}", e);
            return Err(e);
        }

        dhcp_msg.opts_mut().insert(v4::DhcpOption::ClientIdentifier(
            self.config.client_id.clone(),
        ));
        if self.config.use_host_name_as_client_id {
            dhcp_msg.opts_mut().insert(v4::DhcpOption::Hostname(
                self.config.host_name.clone(),
            ));
        }

        log::debug!("DHCP message {:?}", dhcp_msg);

        let mut dhcp_msg_buff = Vec::new();
        let mut e = v4::Encoder::new(&mut dhcp_msg_buff);
        dhcp_msg.encode(&mut e)?;
        Ok(dhcp_msg_buff)
    }

    pub(crate) fn from_dhcp_pkg(payload: &[u8]) -> Result<Self, DhcpError> {
        let v4_dhcp_msg = v4::Message::decode(&mut Decoder::new(payload))
            .map_err(|decode_error| {
                let e = DhcpError::new(
                    ErrorKind::InvalidDhcpServerReply,
                    format!(
                        "Failed to parse DHCP message from payload of pkg \
                        {payload:?}: {decode_error}"
                    ),
                );
                log::error!("{}", e);
                e
            })?;

        let msg_type = match v4_dhcp_msg.opts().get(v4::OptionCode::MessageType)
        {
            Some(v4::DhcpOption::MessageType(v4::MessageType::Offer)) => {
                DhcpV4MessageType::Offer
            }
            Some(v4::DhcpOption::MessageType(v4::MessageType::Ack)) => {
                DhcpV4MessageType::Ack
            }
            Some(t) => {
                log::debug!("Unknown dhcp message type {:?}", t);
                DhcpV4MessageType::Unknown
            }
            None => {
                log::debug!("Got no dhcp message type");
                DhcpV4MessageType::Unknown
            }
        };
        let ret = Self {
            lease: Some(DhcpV4Lease::try_from(&v4_dhcp_msg)?),
            msg_type,
            xid: v4_dhcp_msg.xid(),
            ..Default::default()
        };
        log::debug!("Got reply DHCP message {:?}", ret);
        Ok(ret)
    }

    pub(crate) fn to_eth_pkg_broadcast(&self) -> Result<Vec<u8>, DhcpError> {
        let dhcp_msg_buff = self.to_dhcp_pkg()?;
        gen_eth_pkg(
            &mac_address_to_eth_mac_bytes(&self.config.src_mac)?,
            &BROADCAST_MAC_ADDRESS,
            &Ipv4Addr::new(0, 0, 0, 0),
            &Ipv4Addr::new(255, 255, 255, 255),
            dhcproto::v4::CLIENT_PORT,
            dhcproto::v4::SERVER_PORT,
            &dhcp_msg_buff,
        )
    }

    pub(crate) fn to_proxy_eth_pkg_unicast(
        &self,
    ) -> Result<Vec<u8>, DhcpError> {
        if let Some(lease) = self.lease.as_ref() {
            let dhcp_msg_buff = self.to_dhcp_pkg()?;
            gen_eth_pkg(
                &mac_address_to_eth_mac_bytes(&self.config.src_mac)?,
                &lease.srv_mac,
                &lease.yiaddr,
                &lease.siaddr,
                dhcproto::v4::CLIENT_PORT,
                dhcproto::v4::SERVER_PORT,
                &dhcp_msg_buff,
            )
        } else {
            Err(DhcpError::new(
                ErrorKind::Bug,
                "No lease found for `to_proxy_eth_pkg_unicast()`".to_string(),
            ))
        }
    }

    pub(crate) fn from_eth_pkg(data: &[u8]) -> Result<Self, DhcpError> {
        let pkg = match etherparse::SlicedPacket::from_ethernet(data) {
            Err(error) => {
                let e = DhcpError::new(
                    ErrorKind::InvalidDhcpServerReply,
                    format!(
                        "Failed to parse ethernet package to Dhcpv4Offer: {error}"
                    ),
                );
                log::error!("{}", e);
                return Err(e);
            }
            Ok(v) => v,
        };

        let ip = pkg.ip.unwrap();
        let transport = pkg.transport.unwrap();
        let is_ipv4 = match ip {
            etherparse::InternetSlice::Ipv4(_, _) => true,
            _ => false,
        };
        let matches_dhcp_ports = match transport {
            etherparse::TransportSlice::Udp(udp) => {
                let sport = udp.source_port();
                let dport = udp.destination_port();
                (sport == 67 || sport == 68) && (dport == 67 || dport == 68)
            }
            _ => false,
        };
        if !(is_ipv4 && matches_dhcp_ports) {
            let e = DhcpError::new(
                ErrorKind::InvalidDhcpServerReply,
                format!("Invalid DHCP package"),
            );
            log::error!("{}", e);
            return Err(e);
        }

        let mut ret = Self::from_dhcp_pkg(pkg.payload)?;
        if let Some(eth_header) = pkg.link.map(|l| l.to_header()) {
            if let Some(lease) = ret.lease.as_mut() {
                lease.srv_mac = eth_header.source;
            }
        }
        Ok(ret)
    }
}

fn gen_eth_pkg(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: &Ipv4Addr,
    dst_ip: &Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, DhcpError> {
    let builder = etherparse::PacketBuilder::ethernet2(*src_mac, *dst_mac)
        .ipv4(src_ip.octets(), dst_ip.octets(), DEFAULT_TTL)
        .udp(src_port, dst_port);

    let mut pkg = Vec::<u8>::with_capacity(builder.size(payload.len()));

    builder.write(&mut pkg, payload)?;

    Ok(pkg)
}
