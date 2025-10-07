// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv4Addr;

use super::{
    option::DhcpV4Options,
    socket::{CLIENT_PORT, SERVER_PORT},
};
use crate::{
    mac::BROADCAST_MAC_ADDRESS, Buffer, BufferMut, DhcpError, DhcpV4Config,
    DhcpV4Lease, DhcpV4Option, DhcpV4OptionCode, ErrorContext, ErrorKind,
};

const DEFAULT_TTL: u8 = 128;

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash, Default)]
#[repr(u8)]
#[non_exhaustive]
pub enum DhcpV4MessageType {
    #[default]
    Discovery = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nack = 6,
    Release = 7,
    Inform = 8,
}

impl std::fmt::Display for DhcpV4MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Discovery => write!(f, "DISCOVERY"),
            Self::Offer => write!(f, "OFFER"),
            Self::Request => write!(f, "REQUEST"),
            Self::Ack => write!(f, "ACK"),
            Self::Nack => write!(f, "NACK"),
            Self::Decline => write!(f, "DECLINE"),
            Self::Release => write!(f, "RELEASE"),
            Self::Inform => write!(f, "INFORM"),
        }
    }
}

impl std::convert::TryFrom<u8> for DhcpV4MessageType {
    type Error = DhcpError;

    fn try_from(d: u8) -> Result<Self, DhcpError> {
        match d {
            d if d == Self::Discovery as u8 => Ok(Self::Discovery),
            d if d == Self::Offer as u8 => Ok(Self::Offer),
            d if d == Self::Request as u8 => Ok(Self::Request),
            d if d == Self::Decline as u8 => Ok(Self::Decline),
            d if d == Self::Ack as u8 => Ok(Self::Ack),
            d if d == Self::Nack as u8 => Ok(Self::Nack),
            d if d == Self::Release as u8 => Ok(Self::Release),
            d if d == Self::Inform as u8 => Ok(Self::Inform),
            _ => Err(DhcpError::new(
                ErrorKind::NotSupported,
                format!("DHCPv4 message type {d} is not supported"),
            )),
        }
    }
}

const MAX_CHADDR_LEN: usize = 16;
const MAX_SNAME_LEN: usize = 64;
const MAX_FILE_LEN: usize = 128;

#[derive(Debug)]
pub(crate) struct DhcpV4Message {
    /// Message op code / message type. 1 = BOOTREQUEST, 2 = BOOTREPLY
    pub(crate) op: u8,
    /// Hardware address type
    pub(crate) htype: u8,
    /// Hardware address length
    pub(crate) hlen: u8,
    /// Client sets to zero, optionally used by relay agents when booting via a
    /// relay agent.
    pub(crate) hops: u8,
    /// Transaction ID
    pub(crate) xid: u32,
    /// Filled in by client, seconds elapsed since client began address
    /// acquisition or renewal process.
    pub(crate) secs: u16,
    pub(crate) flags: u16,
    /// Client IP address; only filled in if client is in BOUND, RENEW or
    /// REBINDING state and can respond to ARP requests.
    pub(crate) ciaddr: Ipv4Addr,
    /// 'your' (client) IP address.
    pub(crate) yiaddr: Ipv4Addr,
    /// IP address of next server to use in bootstrap; returned in DHCPOFFER,
    /// DHCPACK by server.
    pub(crate) siaddr: Ipv4Addr,
    /// Relay agent IP address, used in booting via a relay agent.
    pub(crate) giaddr: Ipv4Addr,
    /// Client hardware address.
    pub(crate) chaddr: [u8; MAX_CHADDR_LEN],
    /// Optional server host name, null terminated string.
    pub(crate) sname: String,
    /// Boot file name, null terminated string.
    pub(crate) file: String,
    /// DHCP options
    pub(crate) options: DhcpV4Options,
    // Not defined in RFC, crate private use only
    pub(crate) srv_mac: Vec<u8>,
}

const BOOTREQUEST: u8 = 1;
const ARP_HW_TYPE_ETHERNET: u8 = 1;
const HW_ADDR_LEN_ETHERNET: u8 = 6;
const DHCPV4_MAGIC_COOKIE: [u8; 4] = [99u8, 130, 83, 99];

impl Default for DhcpV4Message {
    fn default() -> Self {
        Self {
            op: BOOTREQUEST,
            htype: ARP_HW_TYPE_ETHERNET,
            hlen: HW_ADDR_LEN_ETHERNET,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0u8; MAX_CHADDR_LEN],
            sname: String::new(),
            file: String::new(),
            options: DhcpV4Options::default(),
            srv_mac: Vec::new(),
        }
    }
}

impl DhcpV4Message {
    // The header is 236 bytes, plus 3 bytes for the mandatory option
    // `DHCP Message Type(53)`
    const MIN_LEN: usize = 239;

    /// Parse from raw DHCP message with UDP and lower layer headers purged.
    pub(crate) fn parse(raw: &[u8]) -> Result<Self, DhcpError> {
        if raw.len() < Self::MIN_LEN {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!(
                    "RAW data length({}) is less than minimum DHCP
                    message size{}",
                    raw.len(),
                    Self::MIN_LEN
                ),
            ));
        }
        let mut buf = Buffer::new(raw);

        let mut ret = Self {
            srv_mac: Vec::new(),
            op: buf.get_u8().context("Invalid DHCPv4 header option 'op'")?,
            htype: buf
                .get_u8()
                .context("Invalid DHCPv4 header option 'htype'")?,
            hlen: buf
                .get_u8()
                .context("Invalid DHCPv4 header option 'hlen'")?,
            hops: buf
                .get_u8()
                .context("Invalid DHCPv4 header option 'hops'")?,
            xid: buf
                .get_u32_be()
                .context("Invalid DHCPv4 header option 'xid'")?,
            secs: buf
                .get_u16_be()
                .context("Invalid DHCPv4 header option 'secs'")?,
            flags: buf
                .get_u16_be()
                .context("Invalid DHCPv4 header option 'flags'")?,
            ciaddr: buf
                .get_ipv4()
                .context("Invalid DHCPv4 header option 'ciaddr'")?,
            yiaddr: buf
                .get_ipv4()
                .context("Invalid DHCPv4 header option 'yiaddr'")?,
            siaddr: buf
                .get_ipv4()
                .context("Invalid DHCPv4 header option 'siaddr'")?,
            giaddr: buf
                .get_ipv4()
                .context("Invalid DHCPv4 header option 'giaddr'")?,
            chaddr: {
                let mut chaddr = [0u8; MAX_CHADDR_LEN];
                chaddr.copy_from_slice(
                    buf.get_bytes(MAX_CHADDR_LEN)
                        .context("Invalid DHCPv4 header option 'chaddr'")?,
                );
                chaddr
            },
            sname: buf
                .get_string_with_null(MAX_SNAME_LEN)
                .context("Invalid DHCPv4 header option 'sname' ")?,
            file: buf
                .get_string_with_null(MAX_FILE_LEN)
                .context("Invalid DHCPv4 header option 'file'")?,
            options: DhcpV4Options::new(),
        };

        let magic_cookie =
            buf.get_bytes(4).context("Invalid DHCP magic cookie")?;
        if magic_cookie != DHCPV4_MAGIC_COOKIE {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!(
                    "DHCPv4 magic cookie not match, expected {:?}, got {:?}",
                    DHCPV4_MAGIC_COOKIE, magic_cookie
                ),
            ));
        }
        ret.options = DhcpV4Options::parse(buf.get_remains())?;

        log::trace!("Parsed DHCP message {ret:?}");
        Ok(ret)
    }

    pub(crate) fn parse_eth_packet(buf: &[u8]) -> Result<Self, DhcpError> {
        let packet = match etherparse::SlicedPacket::from_ethernet(buf) {
            Err(error) => {
                return Err(DhcpError::new(
                    ErrorKind::InvalidDhcpMessage,
                    format!(
                        "Failed to parse ethernet package to DHCP message: \
                         {error}"
                    ),
                ));
            }
            Ok(v) => v,
        };
        if let Some(etherparse::TransportSlice::Udp(udp_packet)) =
            packet.transport
        {
            let mut ret = Self::parse(udp_packet.payload())?;
            // TODO(Gris Ge): Do we really need this?
            if let Some(eth_header) = packet
                .link
                .and_then(|l| l.to_header())
                .and_then(|h| h.ethernet2())
            {
                ret.srv_mac = eth_header.source.to_vec();
            }
            Ok(ret)
        } else {
            Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                "Failed to parse ethernet package to DHCP message: Not UDP \
                 payload"
                    .to_string(),
            ))
        }
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        buf.write_u8(self.op);
        buf.write_u8(self.htype);
        buf.write_u8(self.hlen);
        buf.write_u8(self.hops);
        buf.write_u32_be(self.xid);
        buf.write_u16_be(self.secs);
        buf.write_u16_be(self.flags);
        buf.write_ipv4(self.ciaddr);
        buf.write_ipv4(self.yiaddr);
        buf.write_ipv4(self.siaddr);
        buf.write_ipv4(self.giaddr);
        buf.write_bytes(&self.chaddr);
        buf.write_string_with_null(&self.sname, MAX_SNAME_LEN);
        buf.write_string_with_null(&self.file, MAX_FILE_LEN);
        buf.write_bytes(&DHCPV4_MAGIC_COOKIE);
        self.options.emit(buf);
    }

    pub(crate) fn to_eth_packet_broadcast(&self) -> Result<Vec<u8>, DhcpError> {
        log::trace!("Generating ethernet broadcast for DHCP message {self:?}");
        let mut buf = BufferMut::new(Self::MIN_LEN);
        self.emit(&mut buf);
        log::trace!("DHCP packet generated {:?}", buf.data);

        gen_eth_packet(
            &self.chaddr,
            &BROADCAST_MAC_ADDRESS,
            &Ipv4Addr::new(0, 0, 0, 0),
            &Ipv4Addr::new(255, 255, 255, 255),
            CLIENT_PORT,
            SERVER_PORT,
            &buf.data,
        )
    }

    pub(crate) fn to_proxy_eth_packet_unicast(
        &self,
        lease: &DhcpV4Lease,
    ) -> Result<Vec<u8>, DhcpError> {
        let dhcp_msg_buff = self.to_dhcp_packet()?;
        gen_eth_packet(
            &self.chaddr,
            &lease.srv_mac,
            &lease.yiaddr,
            &lease.siaddr,
            CLIENT_PORT,
            SERVER_PORT,
            &dhcp_msg_buff,
        )
    }

    pub(crate) fn to_dhcp_packet(&self) -> Result<Vec<u8>, DhcpError> {
        let mut buf = BufferMut::new(Self::MIN_LEN);
        self.emit(&mut buf);
        Ok(buf.data)
    }

    fn new(xid: u32, config: &DhcpV4Config) -> Self {
        let mut ret = Self {
            xid,
            ..Default::default()
        };
        ret.chaddr[..config.src_mac.len()].copy_from_slice(&config.src_mac);
        if !config.host_name.is_empty() {
            ret.options
                .insert(DhcpV4Option::HostName(config.host_name.clone()));
        }
        ret.options
            .insert(DhcpV4Option::ClientIdentifier(config.client_id.to_vec()));
        ret
    }

    pub(crate) fn new_discovery(xid: u32, config: &DhcpV4Config) -> Self {
        let mut ret = Self::new(xid, config);
        ret.options
            .insert(DhcpV4Option::MessageType(DhcpV4MessageType::Discovery));
        ret.options.insert(DhcpV4Option::ParameterRequestList(
            config.request_opts.to_vec(),
        ));
        ret
    }

    pub(crate) fn new_request(
        xid: u32,
        config: &DhcpV4Config,
        lease: &DhcpV4Lease,
    ) -> Self {
        let mut ret = Self::new(xid, config);
        ret.options
            .insert(DhcpV4Option::MessageType(DhcpV4MessageType::Request));
        ret.options
            .insert(DhcpV4Option::ServerIdentifier(lease.srv_id));
        if lease.srv_id != Ipv4Addr::UNSPECIFIED {
            ret.options
                .insert(DhcpV4Option::ServerIdentifier(lease.srv_id));
        } else {
            ret.options
                .insert(DhcpV4Option::ServerIdentifier(lease.siaddr));
        }
        ret.options
            .insert(DhcpV4Option::RequestedIpAddress(lease.yiaddr));
        ret.options.insert(DhcpV4Option::ParameterRequestList(
            config.request_opts.to_vec(),
        ));
        ret
    }

    pub(crate) fn new_renew(
        xid: u32,
        config: &DhcpV4Config,
        lease: &DhcpV4Lease,
    ) -> Self {
        let mut ret = Self::new_request(xid, config, lease);
        ret.ciaddr = lease.yiaddr;
        ret
    }

    pub(crate) fn new_rebind(
        xid: u32,
        config: &DhcpV4Config,
        lease: &DhcpV4Lease,
    ) -> Self {
        Self::new_renew(xid, config, lease)
    }

    pub(crate) fn new_release(
        xid: u32,
        config: &DhcpV4Config,
        lease: &DhcpV4Lease,
    ) -> Self {
        let mut ret = Self::new_request(xid, config, lease);
        ret.options
            .insert(DhcpV4Option::MessageType(DhcpV4MessageType::Release));
        ret
    }

    pub(crate) fn message_type(&self) -> Option<DhcpV4MessageType> {
        self.options
            .get(DhcpV4OptionCode::MessageType)
            .and_then(|opt| {
                if let DhcpV4Option::MessageType(t) = opt {
                    Some(*t)
                } else {
                    None
                }
            })
    }

    pub(crate) fn lease(&self) -> Option<DhcpV4Lease> {
        match DhcpV4Lease::new_from_msg(self) {
            Ok(l) => Some(l),
            Err(e) => {
                log::debug!("{e}");
                None
            }
        }
    }
}

fn gen_eth_packet(
    src_mac: &[u8],
    dst_mac: &[u8],
    src_ip: &Ipv4Addr,
    dst_ip: &Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, DhcpError> {
    const ETH_MAC_LEN: usize = HW_ADDR_LEN_ETHERNET as usize;
    let mut src_mac_raw = [0u8; ETH_MAC_LEN];
    let mut dst_mac_raw = [0u8; ETH_MAC_LEN];

    if src_mac.len() < ETH_MAC_LEN {
        src_mac_raw[..src_mac.len()].copy_from_slice(src_mac)
    } else {
        src_mac_raw.copy_from_slice(&src_mac[..ETH_MAC_LEN])
    }

    if dst_mac.len() < ETH_MAC_LEN {
        dst_mac_raw[..dst_mac.len()].copy_from_slice(dst_mac)
    } else {
        dst_mac_raw.copy_from_slice(&dst_mac[..ETH_MAC_LEN])
    }

    let builder =
        etherparse::PacketBuilder::ethernet2(src_mac_raw, dst_mac_raw)
            .ipv4(src_ip.octets(), dst_ip.octets(), DEFAULT_TTL)
            .udp(src_port, dst_port);

    let mut packet = Vec::<u8>::with_capacity(builder.size(payload.len()));

    builder.write(&mut packet, payload).map_err(|e| {
        DhcpError::new(
            ErrorKind::Bug,
            format!("Failed to generate ethernet packet: {e}"),
        )
    })?;

    Ok(packet)
}
