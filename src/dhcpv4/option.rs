// SPDX-License-Identifier: Apache-2.0

use std::{cmp::Ordering, collections::HashMap, net::Ipv4Addr};

use super::msg::DhcpV4MessageType;
use crate::{Buffer, BufferMut, DhcpError, ErrorContext};

/// DHCPv4 Option code(u8) defined by RFC 2132
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum DhcpV4OptionCode {
    Pad,
    End,
    HostName,
    RequestedIpAddress,
    MessageType,
    ParameterRequestList,
    ClientIdentifier,
    RenewalTime,
    RebindingTime,
    InterfaceMtu,
    IpAddressLeaseTime,
    SubnetMask,
    BroadcastAddress,
    DomainNameServer,
    Router,
    NtpServers,
    DomainName,
    /// Classless Static Route (RFC 3442)
    ClasslessStaticRoute,
    ServerIdentifier,
    Message,
    Other(u8),
}

const CODE_PAD: u8 = 0;
const CODE_SUBNET_MASK: u8 = 1;
const CODE_ROUTER: u8 = 3;
const CODE_DOMAIN_NAME_SERVER: u8 = 6;
const CODE_HOST_NAME: u8 = 12;
const CODE_DOMAIN_NAME: u8 = 15;
const CODE_INTERFACE_MTU: u8 = 26;
const CODE_BROADCAST_ADDRESS: u8 = 28;
const CODE_NTP_SERVERS: u8 = 42;
const CODE_REQUESTED_IP_ADDRESS: u8 = 50;
const CODE_IP_ADDRESS_LEASE_TIME: u8 = 51;
const CODE_MESSAGE_TYPE: u8 = 53;
const CODE_SERVER_IDENTIFIER: u8 = 54;
const CODE_PARAMETER_REQUEST_LIST: u8 = 55;
const CODE_MESSAGE: u8 = 56;
const CODE_RENEWAL_TIME: u8 = 58;
const CODE_REBIND_TIME: u8 = 59;
const CODE_CLIENT_IDENTIFIER: u8 = 61;
const CODE_CLASSLESS_STATIC_ROUTE: u8 = 121;
const CODE_END: u8 = 255;

impl From<DhcpV4OptionCode> for u8 {
    fn from(v: DhcpV4OptionCode) -> u8 {
        match v {
            DhcpV4OptionCode::Pad => CODE_PAD,
            DhcpV4OptionCode::HostName => CODE_HOST_NAME,
            DhcpV4OptionCode::MessageType => CODE_MESSAGE_TYPE,
            DhcpV4OptionCode::ParameterRequestList => {
                CODE_PARAMETER_REQUEST_LIST
            }
            DhcpV4OptionCode::ClientIdentifier => CODE_CLIENT_IDENTIFIER,
            DhcpV4OptionCode::End => CODE_END,
            DhcpV4OptionCode::RequestedIpAddress => CODE_REQUESTED_IP_ADDRESS,
            DhcpV4OptionCode::ServerIdentifier => CODE_SERVER_IDENTIFIER,
            DhcpV4OptionCode::RenewalTime => CODE_RENEWAL_TIME,
            DhcpV4OptionCode::RebindingTime => CODE_REBIND_TIME,
            DhcpV4OptionCode::InterfaceMtu => CODE_INTERFACE_MTU,
            DhcpV4OptionCode::IpAddressLeaseTime => CODE_IP_ADDRESS_LEASE_TIME,
            DhcpV4OptionCode::SubnetMask => CODE_SUBNET_MASK,
            DhcpV4OptionCode::BroadcastAddress => CODE_BROADCAST_ADDRESS,
            DhcpV4OptionCode::DomainNameServer => CODE_DOMAIN_NAME_SERVER,
            DhcpV4OptionCode::Router => CODE_ROUTER,
            DhcpV4OptionCode::NtpServers => CODE_NTP_SERVERS,
            DhcpV4OptionCode::DomainName => CODE_DOMAIN_NAME,
            DhcpV4OptionCode::ClasslessStaticRoute => {
                CODE_CLASSLESS_STATIC_ROUTE
            }
            DhcpV4OptionCode::Message => CODE_MESSAGE,
            DhcpV4OptionCode::Other(d) => d,
        }
    }
}

impl From<u8> for DhcpV4OptionCode {
    fn from(d: u8) -> Self {
        match d {
            CODE_PAD => Self::Pad,
            CODE_HOST_NAME => Self::HostName,
            CODE_MESSAGE_TYPE => Self::MessageType,
            CODE_PARAMETER_REQUEST_LIST => Self::ParameterRequestList,
            CODE_CLIENT_IDENTIFIER => Self::ClientIdentifier,
            CODE_END => Self::End,
            CODE_REQUESTED_IP_ADDRESS => Self::RequestedIpAddress,
            CODE_SERVER_IDENTIFIER => Self::ServerIdentifier,
            CODE_RENEWAL_TIME => Self::RenewalTime,
            CODE_REBIND_TIME => Self::RebindingTime,
            CODE_INTERFACE_MTU => Self::InterfaceMtu,
            CODE_IP_ADDRESS_LEASE_TIME => Self::IpAddressLeaseTime,
            CODE_SUBNET_MASK => Self::SubnetMask,
            CODE_BROADCAST_ADDRESS => Self::BroadcastAddress,
            CODE_DOMAIN_NAME_SERVER => Self::DomainNameServer,
            CODE_ROUTER => Self::Router,
            CODE_NTP_SERVERS => Self::NtpServers,
            CODE_DOMAIN_NAME => Self::DomainName,
            CODE_CLASSLESS_STATIC_ROUTE => Self::ClasslessStaticRoute,
            CODE_MESSAGE => Self::Message,
            _ => Self::Other(d),
        }
    }
}

impl DhcpV4OptionCode {
    // Microsoft Classless Static Route Option, data format is identical to
    // RFC 3442: Classless Static Route Option(121)
    pub(crate) const MS_CLASSLESS_STATIC_ROUTE: Self = Self::Other(249);
}

/// DHCPv4 Option defined by RFC 2132
#[derive(Debug, PartialEq, Clone)]
pub enum DhcpV4Option {
    Pad,
    End,
    HostName(String),
    MessageType(DhcpV4MessageType),
    ParameterRequestList(Vec<DhcpV4OptionCode>),
    ClientIdentifier(Vec<u8>),
    RequestedIpAddress(Ipv4Addr),
    ServerIdentifier(Ipv4Addr),
    RenewalTime(u32),
    RebindingTime(u32),
    InterfaceMtu(u16),
    IpAddressLeaseTime(u32),
    SubnetMask(Ipv4Addr),
    BroadcastAddress(Ipv4Addr),
    DomainNameServer(Vec<Ipv4Addr>),
    Router(Vec<Ipv4Addr>),
    NtpServers(Vec<Ipv4Addr>),
    DomainName(String),
    ClasslessStaticRoute(Vec<DhcpV4ClasslessRoute>),
    Message(String),
    Unknown(DhcpV4OptionUnknown),
}

impl DhcpV4Option {
    pub fn code(&self) -> DhcpV4OptionCode {
        match self {
            Self::Pad => DhcpV4OptionCode::Pad,
            Self::End => DhcpV4OptionCode::End,
            Self::HostName(_) => DhcpV4OptionCode::HostName,
            Self::MessageType(_) => DhcpV4OptionCode::MessageType,
            Self::ParameterRequestList(_) => {
                DhcpV4OptionCode::ParameterRequestList
            }
            Self::ClientIdentifier(_) => DhcpV4OptionCode::ClientIdentifier,
            Self::ServerIdentifier(_) => DhcpV4OptionCode::ServerIdentifier,
            Self::RequestedIpAddress(_) => DhcpV4OptionCode::RequestedIpAddress,
            Self::RenewalTime(_) => DhcpV4OptionCode::RenewalTime,
            Self::RebindingTime(_) => DhcpV4OptionCode::RebindingTime,
            Self::InterfaceMtu(_) => DhcpV4OptionCode::InterfaceMtu,
            Self::IpAddressLeaseTime(_) => DhcpV4OptionCode::IpAddressLeaseTime,
            Self::SubnetMask(_) => DhcpV4OptionCode::SubnetMask,
            Self::DomainNameServer(_) => DhcpV4OptionCode::DomainNameServer,
            Self::Router(_) => DhcpV4OptionCode::Router,
            Self::NtpServers(_) => DhcpV4OptionCode::NtpServers,
            Self::DomainName(_) => DhcpV4OptionCode::DomainName,
            Self::ClasslessStaticRoute(_) => {
                DhcpV4OptionCode::ClasslessStaticRoute
            }
            Self::BroadcastAddress(_) => DhcpV4OptionCode::BroadcastAddress,
            Self::Message(_) => DhcpV4OptionCode::Message,
            Self::Unknown(v) => v.code.into(),
        }
    }

    pub(crate) fn parse(buf: &mut Buffer) -> Result<Self, DhcpError> {
        let code: DhcpV4OptionCode =
            buf.get_u8().context("No DHCPv4 option code found")?.into();
        let len: usize = if code == DhcpV4OptionCode::Pad {
            return Ok(Self::Pad);
        } else if code == DhcpV4OptionCode::End {
            return Ok(Self::End);
        } else {
            buf.get_u8()
                .context(format!(
                    "No length for DHCPv4 option {}",
                    u8::from(code)
                ))?
                .into()
        };

        Ok(match code {
            DhcpV4OptionCode::Pad => Self::Pad,
            DhcpV4OptionCode::End => Self::End,
            DhcpV4OptionCode::HostName => Self::HostName(
                buf.get_string_with_null(len)
                    .context("Invalid DHCPv4 option for host name(12)")?,
            ),
            DhcpV4OptionCode::MessageType => Self::MessageType(
                buf.get_u8()
                    .context("Invalid DHCPv4 option for message type(53)")?
                    .try_into()?,
            ),
            DhcpV4OptionCode::ParameterRequestList => {
                let opt_list_raw = buf.get_bytes(len).context(
                    "Invalid DHCPv4 option for parameter request list",
                )?;

                let mut opt_list: Vec<DhcpV4OptionCode> =
                    Vec::with_capacity(len);
                for opt in opt_list_raw {
                    opt_list.push((*opt).into());
                }
                Self::ParameterRequestList(opt_list)
            }
            DhcpV4OptionCode::ClientIdentifier => Self::ClientIdentifier(
                buf.get_bytes(len)
                    .context("Invalid DHCPv4 option for client identifier(61)")?
                    .to_vec(),
            ),
            DhcpV4OptionCode::RequestedIpAddress => {
                Self::RequestedIpAddress(buf.get_ipv4().context(
                    "Invalid DHCPv4 option for requested IP address(50)",
                )?)
            }
            DhcpV4OptionCode::ServerIdentifier => {
                Self::ServerIdentifier(buf.get_ipv4().context(
                    "Invalid DHCPv4 option for server identifier(54)",
                )?)
            }
            DhcpV4OptionCode::RenewalTime => {
                Self::RenewalTime(buf.get_u32_be().context(
                    "Invalid DHCPv4 option for renewal(T1) time(58)",
                )?)
            }
            DhcpV4OptionCode::RebindingTime => Self::RebindingTime(
                buf.get_u32_be()
                    .context("Invalid DHCPv4 option for rebind(T2) time(59)")?,
            ),
            DhcpV4OptionCode::InterfaceMtu => Self::InterfaceMtu(
                buf.get_u16_be()
                    .context("Invalid DHCPv4 option for interface MTU(26)")?,
            ),
            DhcpV4OptionCode::IpAddressLeaseTime => {
                Self::IpAddressLeaseTime(buf.get_u32_be().context(
                    "Invalid DHCPv4 option for IP address lease time(51)",
                )?)
            }
            DhcpV4OptionCode::SubnetMask => Self::SubnetMask(
                buf.get_ipv4()
                    .context("Invalid DHCPv4 option for subnet mask(1)")?,
            ),
            DhcpV4OptionCode::BroadcastAddress => {
                Self::BroadcastAddress(buf.get_ipv4().context(
                    "Invalid DHCPv4 option for broadcast address(28)",
                )?)
            }
            DhcpV4OptionCode::DomainNameServer => Self::DomainNameServer({
                let mut ret = Vec::new();
                for _ in 0..(len / 4_usize) {
                    ret.push(buf.get_ipv4().context(
                        "Invalid DHCPv4 option for domain name server(6)",
                    )?);
                }
                ret
            }),
            DhcpV4OptionCode::Router => Self::Router({
                let mut ret = Vec::new();
                for _ in 0..(len / 4_usize) {
                    ret.push(
                        buf.get_ipv4()
                            .context("Invalid DHCPv4 option for router(3)")?,
                    );
                }
                ret
            }),
            DhcpV4OptionCode::NtpServers => Self::NtpServers({
                let mut ret = Vec::new();
                for _ in 0..(len / 4_usize) {
                    ret.push(buf.get_ipv4().context(
                        "Invalid DHCPv4 option for NTP servers(42)",
                    )?);
                }
                ret
            }),
            DhcpV4OptionCode::DomainName => Self::DomainName(
                buf.get_string_with_null(len)
                    .context("Invalid DHCPv4 option for domain name(15)")?,
            ),
            DhcpV4OptionCode::ClasslessStaticRoute => {
                let raw = buf.get_bytes(len).context(
                    "Invalid DHCPv4 option for classless static routes (121)",
                )?;
                Self::ClasslessStaticRoute({
                    DhcpV4ClasslessRoutes::parse(raw)?
                })
            }
            DhcpV4OptionCode::Message => Self::Message(
                buf.get_string_with_null(len)
                    .context("Invalid DHCPv4 option for message(56)")?,
            ),
            DhcpV4OptionCode::Other(d) => {
                let data = buf
                    .get_bytes(len)
                    .context(format!("Invalid DHCPv4 option {d}"))?
                    .to_vec();
                Self::Unknown(DhcpV4OptionUnknown { code: d, data })
            }
        })
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        buf.write_u8(self.code().into());
        match self {
            Self::Pad | Self::End => (),
            Self::HostName(s) | Self::DomainName(s) | Self::Message(s) => {
                let len = s.len() + 1;
                let len = if len > u8::MAX as usize {
                    log::warn!(
                        "The value of DHCPv4 option {} has exceeded the \
                         maximum length 254, truncating: {s}",
                        u8::from(self.code())
                    );
                    u8::MAX
                } else {
                    len as u8
                };

                buf.write_u8(len);
                buf.write_string_with_null(s.as_str(), u8::MAX.into());
            }
            Self::MessageType(t) => {
                buf.write_u8(1);
                buf.write_u8(*t as u8);
            }
            Self::ParameterRequestList(opts) => {
                buf.write_u8(opts.len() as u8);
                for opt in opts {
                    buf.write_u8(u8::from(*opt));
                }
            }
            Self::ClientIdentifier(id) => {
                buf.write_u8(id.len() as u8);
                buf.write_bytes(id.as_slice());
            }
            Self::RequestedIpAddress(ip)
            | Self::ServerIdentifier(ip)
            | Self::SubnetMask(ip)
            | Self::BroadcastAddress(ip) => {
                buf.write_u8(4);
                buf.write_ipv4(*ip);
            }
            Self::RenewalTime(v)
            | Self::RebindingTime(v)
            | Self::IpAddressLeaseTime(v) => {
                buf.write_u8(4);
                buf.write_u32_be(*v);
            }
            Self::InterfaceMtu(v) => {
                buf.write_u8(2);
                buf.write_u16_be(*v);
            }
            Self::DomainNameServer(ips)
            | Self::Router(ips)
            | Self::NtpServers(ips) => {
                buf.write_u8((ips.len() * 4) as u8);
                for ip in ips {
                    buf.write_ipv4(*ip)
                }
            }
            Self::ClasslessStaticRoute(rts) => {
                DhcpV4ClasslessRoutes::emit(rts.as_slice(), buf);
            }
            Self::Unknown(v) => {
                buf.write_u8(v.data.len() as u8);
                buf.write_bytes(v.data.as_slice());
            }
        }
    }
}

impl Ord for DhcpV4OptionCode {
    fn cmp(&self, other: &Self) -> Ordering {
        u8::from(*self).cmp(&u8::from(*other))
    }
}

impl PartialOrd for DhcpV4OptionCode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, PartialEq, Clone, Default)]
pub(crate) struct DhcpV4Options {
    data: HashMap<DhcpV4OptionCode, DhcpV4Option>,
}

impl DhcpV4Options {
    pub(crate) fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    pub fn get(&self, code: DhcpV4OptionCode) -> Option<&DhcpV4Option> {
        self.data.get(&code)
    }

    pub fn get_data_raw(&self, code: u8) -> Option<Vec<u8>> {
        let mut buf = BufferMut::new();
        self.data.get(&code.into()).map(|v| {
            v.emit(&mut buf);
            buf.data
        })
    }

    pub(crate) fn parse(raw: &[u8]) -> Result<Self, DhcpError> {
        let mut ret = Self::new();
        let mut buf = Buffer::new(raw);

        while !buf.is_empty() {
            match DhcpV4Option::parse(&mut buf) {
                Ok(opt) => {
                    if opt == DhcpV4Option::End {
                        ret.insert(opt);
                        break;
                    } else {
                        ret.insert(opt);
                    }
                }
                Err(e) => {
                    log::info!(
                        "Ignore DHCPv4 option due to parsing error: {e}"
                    );
                    continue;
                }
            }
        }

        Ok(ret)
    }

    pub(crate) fn emit(&self, buff: &mut BufferMut) {
        let mut codes: Vec<DhcpV4OptionCode> =
            self.data.keys().cloned().collect();
        codes.sort_unstable();
        for code in codes {
            if let Some(opt) = self.data.get(&code) {
                opt.emit(buff);
            }
        }
        if !self.data.contains_key(&DhcpV4OptionCode::End) {
            DhcpV4Option::End.emit(buff);
        }
    }

    pub(crate) fn insert(&mut self, opt: DhcpV4Option) {
        self.data.insert(opt.code(), opt);
    }
}

/// Classless Static Route
///
/// Defined by RFC 3442
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
pub struct DhcpV4ClasslessRoute {
    pub destination: Ipv4Addr,
    pub prefix_length: u8,
    pub router: Ipv4Addr,
}

impl DhcpV4ClasslessRoute {
    pub(crate) fn parse(buf: &mut Buffer) -> Result<Self, DhcpError> {
        let err_str = "Invalid DHCPv4 option for classless static route(121)";
        let prefix_length = buf.get_u8().context(err_str)?;
        let destination = match prefix_length {
            0 => Ipv4Addr::UNSPECIFIED,
            1..=8 => Ipv4Addr::new(buf.get_u8().context(err_str)?, 0, 0, 0),
            9..=16 => Ipv4Addr::new(
                buf.get_u8().context(err_str)?,
                buf.get_u8().context(err_str)?,
                0,
                0,
            ),
            17..=24 => Ipv4Addr::new(
                buf.get_u8().context(err_str)?,
                buf.get_u8().context(err_str)?,
                buf.get_u8().context(err_str)?,
                0,
            ),
            _ => buf.get_ipv4().context(err_str)?,
        };

        Ok(Self {
            destination,
            prefix_length,
            router: buf.get_ipv4().context(err_str)?,
        })
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        buf.write_u8(self.prefix_length);
        let dst_octs = self.destination.octets();
        match self.prefix_length {
            0 => (),
            1..=8 => buf.write_u8(dst_octs[0]),
            9..=16 => {
                buf.write_u8(dst_octs[0]);
                buf.write_u8(dst_octs[1]);
            }
            17..=24 => {
                buf.write_u8(dst_octs[0]);
                buf.write_u8(dst_octs[1]);
                buf.write_u8(dst_octs[2]);
            }
            _ => buf.write_ipv4(self.destination),
        }
        buf.write_ipv4(self.router);
    }
}

pub(crate) struct DhcpV4ClasslessRoutes;

impl DhcpV4ClasslessRoutes {
    pub(crate) fn parse(
        buf: &[u8],
    ) -> Result<Vec<DhcpV4ClasslessRoute>, DhcpError> {
        let mut buf = Buffer::new(buf);
        let mut ret: Vec<DhcpV4ClasslessRoute> = Vec::new();
        while !buf.is_empty() {
            ret.push(DhcpV4ClasslessRoute::parse(&mut buf)?);
        }
        Ok(ret)
    }

    pub(crate) fn emit(rts: &[DhcpV4ClasslessRoute], buf: &mut BufferMut) {
        let mut tmp_buf = BufferMut::new();
        for rt in rts {
            rt.emit(&mut tmp_buf);
        }
        buf.write_u8(tmp_buf.len() as u8);
        buf.write_bytes(tmp_buf.data.as_slice());
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct DhcpV4OptionUnknown {
    pub code: u8,
    pub data: Vec<u8>,
}
