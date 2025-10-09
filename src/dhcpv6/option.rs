// SPDX-License-Identifier: Apache-2.0

use std::{cmp::Ordering, collections::HashMap, net::Ipv6Addr};

use crate::{
    Buffer, BufferMut, DhcpError, DhcpV6Duid, DhcpV6OptionIaAddr,
    DhcpV6OptionIaNa, DhcpV6OptionIaPd, DhcpV6OptionIaPrefix, DhcpV6OptionIaTa,
    DhcpV6OptionStatus, ErrorContext, ErrorKind,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub(crate) struct DhcpV6Options {
    data: HashMap<DhcpV6OptionCode, Vec<DhcpV6Option>>,
}

impl DhcpV6Options {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn get_data_raw(&self, code: u16) -> Option<Vec<Vec<u8>>> {
        let mut ret: Vec<Vec<u8>> = Vec::new();
        if let Some(opts) = self.data.get(&DhcpV6OptionCode::from(code)) {
            for opt in opts {
                let mut buf = BufferMut::new();
                opt.emit(&mut buf);
                ret.push(buf.data);
            }
            Some(ret)
        } else {
            None
        }
    }

    pub(crate) fn get_first(
        &self,
        code: DhcpV6OptionCode,
    ) -> Option<&DhcpV6Option> {
        self.data
            .get(&code)
            .map(|opts| opts.as_slice())
            .and_then(|opts| opts.first())
    }

    pub(crate) fn insert(&mut self, opt: DhcpV6Option) {
        self.data.entry(opt.code()).or_default().push(opt);
    }

    pub(crate) fn remove(&mut self, code: DhcpV6OptionCode) {
        self.data.remove(&code);
    }

    pub(crate) fn parse(buf: &mut Buffer) -> Result<Self, DhcpError> {
        let mut ret = Self::new();
        while !buf.is_empty() {
            match DhcpV6Option::parse(buf) {
                Ok(opt) => {
                    ret.insert(opt);
                }
                Err(e) => {
                    log::info!(
                        "Ignore DHCPv6 option due to parsing error: {e}"
                    );
                    continue;
                }
            }
        }
        Ok(ret)
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        let mut all_opts: Vec<&DhcpV6Option> = Vec::new();

        for opts in self.data.values() {
            for opt in opts {
                all_opts.push(opt);
            }
        }

        all_opts.sort_unstable();

        for opt in all_opts {
            opt.emit(buf);
        }
    }
}

const OPTION_CLIENTID: u16 = 1;
const OPTION_SERVERID: u16 = 2;
const OPTION_IA_NA: u16 = 3;
const OPTION_IA_TA: u16 = 4;
const OPTION_IAADDR: u16 = 5;
const OPTION_ORO: u16 = 6;
const OPTION_PREFERENCE: u16 = 7;
const OPTION_ELAPSED_TIME: u16 = 8;
const OPTION_UNICAST: u16 = 12;
const OPTION_STATUS_CODE: u16 = 13;
const OPTION_RAPID_COMMIT: u16 = 14;
const OPTION_DNS_SERVERS: u16 = 23;
const OPTION_DOMAIN_LIST: u16 = 24;
const OPTION_IA_PD: u16 = 25;
const OPTION_IAPREFIX: u16 = 26;
const OPTION_NTP_SERVER: u16 = 56;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, Default)]
#[non_exhaustive]
pub enum DhcpV6OptionCode {
    #[default]
    ClientId,
    ServerId,
    IANA,
    IATA,
    IAPD,
    IAAddr,
    IAPrefix,
    OptionRequestOption,
    Preference,
    ElapsedTime,
    ServerUnicast,
    StatusCode,
    RapidCommit,
    DnsServers,
    DomainList,
    NtpServer,
    Other(u16),
}

impl From<DhcpV6OptionCode> for u16 {
    fn from(v: DhcpV6OptionCode) -> u16 {
        match v {
            DhcpV6OptionCode::ClientId => OPTION_CLIENTID,
            DhcpV6OptionCode::ServerId => OPTION_SERVERID,
            DhcpV6OptionCode::IANA => OPTION_IA_NA,
            DhcpV6OptionCode::IATA => OPTION_IA_TA,
            DhcpV6OptionCode::IAPD => OPTION_IA_PD,
            DhcpV6OptionCode::IAAddr => OPTION_IAADDR,
            DhcpV6OptionCode::IAPrefix => OPTION_IAPREFIX,
            DhcpV6OptionCode::OptionRequestOption => OPTION_ORO,
            DhcpV6OptionCode::Preference => OPTION_PREFERENCE,
            DhcpV6OptionCode::ElapsedTime => OPTION_ELAPSED_TIME,
            DhcpV6OptionCode::ServerUnicast => OPTION_UNICAST,
            DhcpV6OptionCode::StatusCode => OPTION_STATUS_CODE,
            DhcpV6OptionCode::RapidCommit => OPTION_RAPID_COMMIT,
            DhcpV6OptionCode::DnsServers => OPTION_DNS_SERVERS,
            DhcpV6OptionCode::DomainList => OPTION_DOMAIN_LIST,
            DhcpV6OptionCode::NtpServer => OPTION_NTP_SERVER,
            DhcpV6OptionCode::Other(d) => d,
        }
    }
}

impl From<u16> for DhcpV6OptionCode {
    fn from(d: u16) -> Self {
        match d {
            OPTION_CLIENTID => Self::ClientId,
            OPTION_SERVERID => Self::ServerId,
            OPTION_IA_NA => Self::IANA,
            OPTION_IA_TA => Self::IATA,
            OPTION_IA_PD => Self::IAPD,
            OPTION_IAADDR => Self::IAAddr,
            OPTION_IAPREFIX => Self::IAPrefix,
            OPTION_ORO => Self::OptionRequestOption,
            OPTION_PREFERENCE => Self::Preference,
            OPTION_ELAPSED_TIME => Self::ElapsedTime,
            OPTION_UNICAST => Self::ServerUnicast,
            OPTION_STATUS_CODE => Self::StatusCode,
            OPTION_RAPID_COMMIT => Self::RapidCommit,
            OPTION_DNS_SERVERS => Self::DnsServers,
            OPTION_DOMAIN_LIST => Self::DomainList,
            OPTION_NTP_SERVER => Self::NtpServer,
            _ => Self::Other(d),
        }
    }
}

impl Ord for DhcpV6OptionCode {
    fn cmp(&self, other: &Self) -> Ordering {
        u16::from(*self).cmp(&u16::from(*other))
    }
}

impl PartialOrd for DhcpV6OptionCode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for DhcpV6OptionCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClientId => write!(f, "OPTION_CLIENTID"),
            Self::ServerId => write!(f, "OPTION_SERVERID"),
            Self::IANA => write!(f, "OPTION_IA_NA"),
            Self::IATA => write!(f, "OPTION_IA_TA"),
            Self::IAPD => write!(f, "OPTION_IA_PD"),
            Self::IAAddr => write!(f, "OPTION_IAADDR"),
            Self::IAPrefix => write!(f, "OPTION_IAPREFIX"),
            Self::OptionRequestOption => write!(f, "OPTION_ORO"),
            Self::Preference => write!(f, "OPTION_PREFERENCE"),
            Self::ElapsedTime => write!(f, "OPTION_ELAPSED_TIME"),
            Self::ServerUnicast => write!(f, "OPTION_UNICAST"),
            Self::StatusCode => write!(f, "OPTION_STATUS_CODE"),
            Self::RapidCommit => write!(f, "OPTION_RAPID_COMMIT"),
            Self::DnsServers => write!(f, "OPTION_DNS_SERVERS"),
            Self::DomainList => write!(f, "OPTION_DOMAIN_LIST"),
            Self::NtpServer => write!(f, "OPTION_NTP_SERVER"),
            Self::Other(d) => write!(f, "Unknown({d})"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum DhcpV6Option {
    ClientId(DhcpV6Duid),
    ServerId(DhcpV6Duid),
    IANA(DhcpV6OptionIaNa),
    IATA(DhcpV6OptionIaTa),
    IAPD(DhcpV6OptionIaPd),
    OptionRequestOption(Vec<DhcpV6OptionCode>),
    IAAddr(DhcpV6OptionIaAddr),
    IAPrefix(DhcpV6OptionIaPrefix),
    Preference(u8),
    ElapsedTime(u16),
    ServerUnicast(Ipv6Addr),
    StatusCode(DhcpV6OptionStatus),
    RapidCommit,
    /// RFC 3646
    DnsServers(Vec<Ipv6Addr>),
    /// RFC 3646
    DomainList(Vec<String>),
    /// RFC 5908
    NtpServer(Vec<DhcpV6OptionNtpServer>),
    Unknown(DhcpV6OptionUnknown),
}

impl Default for DhcpV6Option {
    fn default() -> Self {
        Self::Unknown(DhcpV6OptionUnknown::default())
    }
}

impl Ord for DhcpV6Option {
    fn cmp(&self, other: &Self) -> Ordering {
        self.code().cmp(&other.code())
    }
}

impl PartialOrd for DhcpV6Option {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl DhcpV6Option {
    pub fn code(&self) -> DhcpV6OptionCode {
        match self {
            DhcpV6Option::ClientId(_) => DhcpV6OptionCode::ClientId,
            DhcpV6Option::ServerId(_) => DhcpV6OptionCode::ServerId,
            DhcpV6Option::IANA(_) => DhcpV6OptionCode::IANA,
            DhcpV6Option::IATA(_) => DhcpV6OptionCode::IATA,
            DhcpV6Option::OptionRequestOption(_) => {
                DhcpV6OptionCode::OptionRequestOption
            }
            DhcpV6Option::Preference(_) => DhcpV6OptionCode::Preference,
            DhcpV6Option::ElapsedTime(_) => DhcpV6OptionCode::ElapsedTime,
            DhcpV6Option::ServerUnicast(_) => DhcpV6OptionCode::ServerUnicast,
            DhcpV6Option::StatusCode(_) => DhcpV6OptionCode::StatusCode,
            DhcpV6Option::RapidCommit => DhcpV6OptionCode::RapidCommit,
            DhcpV6Option::DnsServers(_) => DhcpV6OptionCode::DnsServers,
            DhcpV6Option::DomainList(_) => DhcpV6OptionCode::DomainList,
            DhcpV6Option::IAPD(_) => DhcpV6OptionCode::IAPD,
            DhcpV6Option::NtpServer(_) => DhcpV6OptionCode::NtpServer,
            DhcpV6Option::IAAddr(_) => DhcpV6OptionCode::IAAddr,
            DhcpV6Option::IAPrefix(_) => DhcpV6OptionCode::IAPrefix,
            DhcpV6Option::Unknown(u) => u.code(),
        }
    }

    pub(crate) fn parse(buf: &mut Buffer) -> Result<DhcpV6Option, DhcpError> {
        let code: DhcpV6OptionCode = buf
            .peek_u16_be()
            .context("Invalid DHCPv6 option code")?
            .into();
        let len: usize = buf
            .peek_u16_be_offset(2)
            .context("Invalid DHCPv6 option length")?
            .into();
        let opt_raw = buf.get_bytes(len + 4).context(format!(
            "Invalid DHCPv6 option {code} with length {len}"
        ))?;
        let mut opt_buf = Buffer::new(opt_raw);

        Ok(match code {
            DhcpV6OptionCode::IAAddr => {
                Self::IAAddr(DhcpV6OptionIaAddr::parse(&mut opt_buf)?)
            }
            DhcpV6OptionCode::IAPrefix => {
                Self::IAPrefix(DhcpV6OptionIaPrefix::parse(&mut opt_buf)?)
            }
            DhcpV6OptionCode::ClientId => {
                opt_buf.get_u16_be().context("Invalid DHCPv6 option code")?;
                opt_buf
                    .get_u16_be()
                    .context("Invalid DHCPv6 option length")?;
                Self::ClientId(DhcpV6Duid::parse(&mut opt_buf, len)?)
            }
            DhcpV6OptionCode::ServerId => {
                opt_buf.get_u16_be().context("Invalid DHCPv6 option code")?;
                opt_buf
                    .get_u16_be()
                    .context("Invalid DHCPv6 option length")?;
                Self::ServerId(DhcpV6Duid::parse(&mut opt_buf, len)?)
            }
            DhcpV6OptionCode::IANA => {
                Self::IANA(DhcpV6OptionIaNa::parse(&mut opt_buf)?)
            }
            DhcpV6OptionCode::IATA => {
                Self::IATA(DhcpV6OptionIaTa::parse(&mut opt_buf)?)
            }
            DhcpV6OptionCode::IAPD => {
                Self::IAPD(DhcpV6OptionIaPd::parse(&mut opt_buf)?)
            }
            DhcpV6OptionCode::OptionRequestOption => {
                opt_buf.get_u16_be().context("Invalid DHCPv6 option code")?;
                opt_buf
                    .get_u16_be()
                    .context("Invalid DHCPv6 option length")?;
                let mut opts: Vec<DhcpV6OptionCode> = Vec::new();
                for _ in 0..len / 2 {
                    opts.push(
                        opt_buf
                            .get_u16_be()
                            .context("Invalid DHCPv6 option OPTION_ORO")?
                            .into(),
                    );
                }
                Self::OptionRequestOption(opts)
            }
            DhcpV6OptionCode::Preference => Self::Preference({
                opt_buf.get_u16_be().context("Invalid DHCPv6 option code")?;
                opt_buf
                    .get_u16_be()
                    .context("Invalid DHCPv6 option length")?;
                opt_buf
                    .get_u8()
                    .context("Invalid DHCPv6 option OPTION_PREFERENCE")?
            }),
            DhcpV6OptionCode::ElapsedTime => Self::ElapsedTime({
                opt_buf.get_u16_be().context("Invalid DHCPv6 option code")?;
                opt_buf
                    .get_u16_be()
                    .context("Invalid DHCPv6 option length")?;
                opt_buf
                    .get_u16_be()
                    .context("Invalid DHCPv6 option OPTION_ELAPSED_TIME")?
            }),
            DhcpV6OptionCode::ServerUnicast => Self::ServerUnicast({
                opt_buf.get_u16_be().context("Invalid DHCPv6 option code")?;
                opt_buf
                    .get_u16_be()
                    .context("Invalid DHCPv6 option length")?;
                opt_buf
                    .get_ipv6()
                    .context("Invalid DHCPv6 option OPTION_UNICAST")?
            }),
            DhcpV6OptionCode::StatusCode => {
                Self::StatusCode(DhcpV6OptionStatus::parse(&mut opt_buf)?)
            }
            DhcpV6OptionCode::RapidCommit => {
                opt_buf.get_u16_be().context("Invalid DHCPv6 option code")?;
                opt_buf
                    .get_u16_be()
                    .context("Invalid DHCPv6 option length")?;
                Self::RapidCommit
            }
            DhcpV6OptionCode::DnsServers => {
                opt_buf.get_u16_be().context("Invalid DHCPv6 option code")?;
                opt_buf
                    .get_u16_be()
                    .context("Invalid DHCPv6 option length")?;
                let mut addrs = Vec::new();
                for _ in 0..len / 16 {
                    addrs.push(
                        opt_buf.get_ipv6().context(
                            "Invalid DHCPv6 option OPTION_DNS_SERVERS",
                        )?,
                    );
                }
                Self::DnsServers(addrs)
            }
            DhcpV6OptionCode::DomainList => {
                // RFC 1035: 3.1. Name space definitions
                //      Domain names in messages are expressed in terms of a
                //      sequence of labels.  Each label is represented as a one
                //      octet length field followed by that number of octets.
                //      Since every domain name ends with the null label of the
                //      root, a domain name is terminated by a length byte of
                //      zero.  The high order two bits of every length octet
                //      must be zero, and the remaining six bits of the length
                //      field limit the label to 63 octets or less.
                opt_buf.get_u16_be().context("Invalid DHCPv6 option code")?;
                opt_buf
                    .get_u16_be()
                    .context("Invalid DHCPv6 option length")?;
                let raw = opt_buf
                    .get_bytes(len)
                    .context("Invalid DHCPv6 option OPTION_DOMAIN_LIST")?;
                let mut tmp_opt_buf = Buffer::new(raw);
                let mut domains = Vec::new();
                while !tmp_opt_buf.is_empty() {
                    let str_len = tmp_opt_buf.get_u8().context(
                        "Invalid DHCPv6 option OPTION_DOMAIN_LIST length",
                    )?;
                    domains.push(
                        tmp_opt_buf
                            .get_string_with_null(str_len.into())
                            .context(
                                "Invalid DHCPv6 option OPTION_DOMAIN_LIST \
                                 domain",
                            )?,
                    );
                }
                Self::DomainList(domains)
            }
            DhcpV6OptionCode::NtpServer => {
                // RFC 5908
                opt_buf.get_u16_be().context("Invalid DHCPv6 option code")?;
                opt_buf
                    .get_u16_be()
                    .context("Invalid DHCPv6 option length")?;
                let raw = opt_buf
                    .get_bytes(len)
                    .context("Invalid DHCPv6 option OPTION_NTP_SERVER")?;
                let mut tmp_opt_buf = Buffer::new(raw);
                let mut srvs: Vec<DhcpV6OptionNtpServer> = Vec::new();
                while !tmp_opt_buf.is_empty() {
                    srvs.push(DhcpV6OptionNtpServer::parse(&mut tmp_opt_buf)?);
                }
                Self::NtpServer(srvs)
            }
            DhcpV6OptionCode::Other(d) => Self::Unknown({
                opt_buf.get_u16_be().context("Invalid DHCPv6 option code")?;
                opt_buf
                    .get_u16_be()
                    .context("Invalid DHCPv6 option length")?;
                DhcpV6OptionUnknown {
                    code: d,
                    raw: opt_buf
                        .get_bytes(len)
                        .context(format!("Invalid DHCPv6 option {d}"))?
                        .to_vec(),
                }
            }),
        })
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        match self {
            Self::ClientId(id) | Self::ServerId(id) => {
                let mut value_buf = BufferMut::new();
                id.emit(&mut value_buf);
                buf.write_u16_be(self.code().into());
                buf.write_u16_be(value_buf.len() as u16);
                buf.write_bytes(value_buf.data.as_slice());
            }
            Self::IAAddr(v) => v.emit(buf),
            Self::IAPrefix(v) => v.emit(buf),
            Self::IANA(v) => v.emit(buf),
            Self::IATA(v) => v.emit(buf),
            Self::IAPD(v) => v.emit(buf),
            Self::OptionRequestOption(opts) => {
                buf.write_u16_be(self.code().into());
                buf.write_u16_be((opts.len() * 2) as u16);
                for opt in opts {
                    buf.write_u16_be((*opt).into());
                }
            }
            Self::Preference(d) => {
                buf.write_u16_be(self.code().into());
                buf.write_u16_be(1);
                buf.write_u8(*d);
            }
            Self::ElapsedTime(d) => {
                buf.write_u16_be(self.code().into());
                buf.write_u16_be(2);
                buf.write_u16_be(*d);
            }
            Self::ServerUnicast(i) => {
                buf.write_u16_be(self.code().into());
                buf.write_u16_be(16);
                buf.write_ipv6(*i);
            }
            Self::StatusCode(v) => {
                v.emit(buf);
            }
            Self::RapidCommit => {
                buf.write_u16_be(self.code().into());
                buf.write_u16_be(0);
            }
            Self::DnsServers(addrs) => {
                buf.write_u16_be(self.code().into());
                buf.write_u16_be((addrs.len() * 16) as u16);
                for addr in addrs {
                    buf.write_ipv6(*addr);
                }
            }
            Self::DomainList(domains) => {
                let mut value_buf = BufferMut::new();
                for domain in domains {
                    value_buf.write_u8((domain.len() + 1) as u8);
                    value_buf.write_string_with_null(domain, domain.len() + 1);
                }
                buf.write_u16_be(self.code().into());
                buf.write_u16_be(value_buf.len() as u16);
                buf.write_bytes(value_buf.data.as_slice());
            }
            Self::NtpServer(srvs) => {
                let mut value_buf = BufferMut::new();
                for srv in srvs {
                    srv.emit(&mut value_buf);
                }
                buf.write_u16_be(self.code().into());
                buf.write_u16_be(value_buf.len() as u16);
                buf.write_bytes(value_buf.data.as_slice());
            }
            Self::Unknown(v) => {
                buf.write_u16_be(self.code().into());
                buf.write_u16_be(v.raw.len() as u16);
                buf.write_bytes(v.raw.as_slice());
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct DhcpV6OptionUnknown {
    pub code: u16,
    pub raw: Vec<u8>,
}

impl DhcpV6OptionUnknown {
    pub fn code(&self) -> DhcpV6OptionCode {
        self.code.into()
    }
}

/// DHCPv6 Option for NTP Server
///
/// Defined by RFC 5908
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum DhcpV6OptionNtpServer {
    ServerAddr(Ipv6Addr),
    MulticastAddr(Ipv6Addr),
    ServerFqdn(String),
    Other((u16, Vec<u8>)),
}

const NTP_SUBOPTION_SRV_ADDR: u16 = 1;
const NTP_SUBOPTION_MC_ADDR: u16 = 2;
const NTP_SUBOPTION_SRV_FQDN: u16 = 3;

impl DhcpV6OptionNtpServer {
    pub(crate) fn parse(buf: &mut Buffer) -> Result<Self, DhcpError> {
        let subopt_type = buf
            .get_u16_be()
            .context("Invalid OPTION_NTP_SERVER suboption")?;
        let subopt_len = buf
            .get_u16_be()
            .context("Invalid OPTION_NTP_SERVER suboption-len")?;
        Ok(match subopt_type {
            NTP_SUBOPTION_SRV_ADDR => {
                Self::ServerAddr(buf.get_ipv6().context(
                    "Invalid OPTION_NTP_SERVER NTP_SUBOPTION_SRV_ADDR",
                )?)
            }
            NTP_SUBOPTION_MC_ADDR => {
                Self::MulticastAddr(buf.get_ipv6().context(
                    "Invalid OPTION_NTP_SERVER NTP_SUBOPTION_MC_ADDR",
                )?)
            }
            NTP_SUBOPTION_SRV_FQDN => Self::ServerFqdn({
                let mut lables = Vec::new();
                let raw = buf.get_bytes(subopt_len.into()).context(
                    "Invalid OPTION_NTP_SERVER NTP_SUBOPTION_SRV_FQDN",
                )?;
                let mut fqdn_buf = Buffer::new(raw);
                while !fqdn_buf.is_empty() {
                    let lable_len = fqdn_buf.get_u8().context(
                        "Invalid OPTION_NTP_SERVER NTP_SUBOPTION_SRV_FQDN",
                    )?;
                    if lable_len == 0 {
                        break;
                    }
                    let lable_raw =
                        fqdn_buf.get_bytes(lable_len as usize).context(
                            "Invalid OPTION_NTP_SERVER NTP_SUBOPTION_SRV_FQDN",
                        )?;
                    match std::str::from_utf8(lable_raw) {
                        Ok(l) => lables.push(l.to_string()),
                        Err(e) => {
                            return Err(DhcpError::new(
                                ErrorKind::InvalidDhcpMessage,
                                format!(
                                    "Invalid OPTION_NTP_SERVER \
                                     NTP_SUBOPTION_SRV_FQDN: {e}"
                                ),
                            ));
                        }
                    }
                }
                lables.join(".").to_string()
            }),
            _ => Self::Other((
                subopt_type,
                buf.get_bytes(subopt_len.into())
                    .context(format!(
                        "Invalid OPTION_NTP_SERVER {}",
                        subopt_type
                    ))?
                    .to_vec(),
            )),
        })
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        match self {
            Self::ServerAddr(ip) => {
                buf.write_u16_be(NTP_SUBOPTION_SRV_ADDR);
                buf.write_u16_be(16);
                buf.write_ipv6(*ip);
            }
            Self::MulticastAddr(ip) => {
                buf.write_u16_be(NTP_SUBOPTION_MC_ADDR);
                buf.write_u16_be(16);
                buf.write_ipv6(*ip);
            }
            Self::ServerFqdn(name) => {
                buf.write_u16_be(NTP_SUBOPTION_SRV_FQDN);
                buf.write_u16_be((name.len() + 1) as u16);
                buf.write_string_with_null(name, name.len() + 1);
            }
            Self::Other((subopt_type, v)) => {
                buf.write_u16_be(*subopt_type);
                buf.write_u16_be(v.len() as u16);
                buf.write_bytes(v.as_slice());
            }
        }
    }
}
