// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv6Addr;

use crate::{
    buffer::{Buffer, BufferMut},
    DhcpError, DhcpV6Option, DhcpV6OptionCode, DhcpV6OptionStatus,
    ErrorContext, ErrorKind,
};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct DhcpV6OptionIaNa {
    pub iaid: u32,
    pub t1_sec: u32,
    pub t2_sec: u32,
    pub address: Option<DhcpV6OptionIaAddr>,
    pub status: Option<DhcpV6OptionStatus>,
}

impl Default for DhcpV6OptionIaNa {
    fn default() -> Self {
        Self {
            iaid: rand::random(),
            t1_sec: 0,
            t2_sec: 0,
            address: None,
            status: None,
        }
    }
}

impl DhcpV6OptionIaNa {
    pub(crate) const fn code() -> DhcpV6OptionCode {
        DhcpV6OptionCode::IANA
    }

    pub(crate) fn new(
        iaid: u32,
        t1_sec: u32,
        t2_sec: u32,
        address: DhcpV6OptionIaAddr,
    ) -> Self {
        Self {
            iaid,
            t1_sec,
            t2_sec,
            address: Some(address),
            status: None,
        }
    }

    pub fn is_success(&self) -> bool {
        self.address.as_ref().map(|addr| addr.is_success()) == Some(true)
            && (self.status.is_none()
                || self.status.as_ref().map(|s| s.is_success()) == Some(true))
    }

    pub(crate) fn parse(buf: &mut Buffer) -> Result<Self, DhcpError> {
        let code = buf.get_u16_be().context("Invalid DHCPv6 option code")?;
        if code != Self::code().into() {
            return Err(DhcpError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Expecting DHCPv6 option {} code {}, got {}",
                    Self::code(),
                    u16::from(Self::code()),
                    code
                ),
            ));
        }
        let len = buf.get_u16_be().context("Invalid DHCPv6 option len")?;
        let raw = buf
            .get_bytes(len.into())
            .context("Invalid DHCPv6 option OPTION_IA_NA")?;
        let mut buf = Buffer::new(raw);
        let mut ret = Self {
            iaid: buf
                .get_u32_be()
                .context("Invalid DHCPv6 option OPTION_IA_NA IAID")?,
            t1_sec: buf
                .get_u32_be()
                .context("Invalid DHCPv6 option OPTION_IA_NA T1")?,
            t2_sec: buf
                .get_u32_be()
                .context("Invalid DHCPv6 option OPTION_IA_NA T2")?,
            ..Default::default()
        };

        // It could neither OPTION_IAADDR or OPTION_STATUS_CODE
        while !buf.is_empty() {
            let opt = DhcpV6Option::parse(&mut buf)?;
            match opt {
                DhcpV6Option::StatusCode(v) => {
                    ret.status = Some(v);
                }
                DhcpV6Option::IAAddr(v) => {
                    ret.address = Some(v);
                }
                _ => {
                    return Err(DhcpError::new(
                        ErrorKind::InvalidDhcpMessage,
                        format!(
                            "Expecting OPTION_IAADDR or OPTION_STATUS_CODE in \
                             OPTION_IA_NA option field, but got {}",
                            opt.code()
                        ),
                    ));
                }
            }
        }
        Ok(ret)
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        let mut value_buf = BufferMut::new();
        value_buf.write_u32_be(self.iaid);
        value_buf.write_u32_be(self.t1_sec);
        value_buf.write_u32_be(self.t2_sec);
        if let Some(address) = self.address.as_ref() {
            address.emit(&mut value_buf);
        }
        if let Some(status) = self.status.as_ref() {
            status.emit(&mut value_buf);
        }

        buf.write_u16_be(DhcpV6OptionCode::IANA.into());
        buf.write_u16_be(value_buf.len() as u16);
        buf.write_bytes(&value_buf.data);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct DhcpV6OptionIaTa {
    pub iaid: u32,
    pub address: Option<DhcpV6OptionIaAddr>,
    pub status: Option<DhcpV6OptionStatus>,
}

impl Default for DhcpV6OptionIaTa {
    fn default() -> Self {
        Self {
            iaid: rand::random(),
            address: None,
            status: None,
        }
    }
}

impl DhcpV6OptionIaTa {
    pub(crate) fn new(iaid: u32, address: DhcpV6OptionIaAddr) -> Self {
        Self {
            iaid,
            address: Some(address),
            status: None,
        }
    }

    pub fn is_success(&self) -> bool {
        self.address.as_ref().map(|addr| addr.is_success()) == Some(true)
            && (self.status.is_none()
                || self.status.as_ref().map(|s| s.is_success()) == Some(true))
    }

    pub(crate) const fn code() -> DhcpV6OptionCode {
        DhcpV6OptionCode::IATA
    }

    pub(crate) fn parse(buf: &mut Buffer) -> Result<Self, DhcpError> {
        let code = buf.get_u16_be().context("Invalid DHCPv6 option code")?;
        if code != Self::code().into() {
            return Err(DhcpError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Expecting DHCPv6 option {} code {}, got {}",
                    Self::code(),
                    u16::from(Self::code()),
                    code
                ),
            ));
        }
        let len = buf.get_u16_be().context("Invalid DHCPv6 option len")?;
        let raw = buf
            .get_bytes(len.into())
            .context("Invalid DHCPv6 option OPTION_IA_TA")?;
        let mut buf = Buffer::new(raw);
        let mut ret = Self {
            iaid: buf
                .get_u32_be()
                .context("Invalid DHCPv6 option OPTION_IA_TA IAID")?,
            ..Default::default()
        };

        while !buf.is_empty() {
            // It could neither OPTION_IAADDR or OPTION_STATUS_CODE
            let opt = DhcpV6Option::parse(&mut buf)?;
            match opt {
                DhcpV6Option::StatusCode(v) => ret.status = Some(v),
                DhcpV6Option::IAAddr(v) => ret.address = Some(v),
                _ => {
                    return Err(DhcpError::new(
                        ErrorKind::InvalidDhcpMessage,
                        format!(
                            "Expecting OPTION_IAADDR or OPTION_STATUS_CODE in \
                             OPTION_IA_TA option field, but got {}",
                            opt.code()
                        ),
                    ));
                }
            }
        }
        Ok(ret)
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        let mut value_buf = BufferMut::new();
        value_buf.write_u32_be(self.iaid);
        if let Some(address) = self.address.as_ref() {
            address.emit(&mut value_buf);
        }
        if let Some(status) = self.status.as_ref() {
            status.emit(&mut value_buf);
        }

        buf.write_u16_be(DhcpV6OptionCode::IATA.into());
        buf.write_u16_be(value_buf.len() as u16);
        buf.write_bytes(&value_buf.data);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct DhcpV6OptionIaPd {
    pub iaid: u32,
    pub t1_sec: u32,
    pub t2_sec: u32,
    pub prefix: Option<DhcpV6OptionIaPrefix>,
    pub status: Option<DhcpV6OptionStatus>,
}

impl Default for DhcpV6OptionIaPd {
    fn default() -> Self {
        Self {
            iaid: rand::random(),
            t1_sec: 0,
            t2_sec: 0,
            prefix: None,
            status: None,
        }
    }
}

impl DhcpV6OptionIaPd {
    pub fn new_with_hint(prefix_len: u8) -> Self {
        Self {
            prefix: Some(DhcpV6OptionIaPrefix {
                prefix: Ipv6Addr::UNSPECIFIED,
                prefix_len,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    pub fn new(
        iaid: u32,
        t1_sec: u32,
        t2_sec: u32,
        prefix: DhcpV6OptionIaPrefix,
    ) -> Self {
        Self {
            iaid,
            t1_sec,
            t2_sec,
            prefix: Some(prefix),
            status: None,
        }
    }

    pub fn is_success(&self) -> bool {
        self.prefix.as_ref().map(|prefix| prefix.is_success()) == Some(true)
            && (self.status.is_none()
                || self.status.as_ref().map(|s| s.is_success()) == Some(true))
    }

    pub(crate) const fn code() -> DhcpV6OptionCode {
        DhcpV6OptionCode::IAPD
    }

    pub(crate) fn parse(buf: &mut Buffer) -> Result<Self, DhcpError> {
        let code = buf.get_u16_be().context("Invalid DHCPv6 option code")?;
        if code != Self::code().into() {
            return Err(DhcpError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Expecting DHCPv6 option {} code {}, got {}",
                    Self::code(),
                    u16::from(Self::code()),
                    code
                ),
            ));
        }
        let len = buf.get_u16_be().context("Invalid DHCPv6 option len")?;
        let raw = buf
            .get_bytes(len.into())
            .context("Invalid DHCPv6 option OPTION_IA_PD")?;
        let mut buf = Buffer::new(raw);
        let mut ret = Self {
            iaid: buf
                .get_u32_be()
                .context("Invalid DHCPv6 option OPTION_IA_PD IAID")?,
            t1_sec: buf
                .get_u32_be()
                .context("Invalid DHCPv6 option OPTION_IA_PD T1")?,
            t2_sec: buf
                .get_u32_be()
                .context("Invalid DHCPv6 option OPTION_IA_PD T2")?,
            ..Default::default()
        };

        // It could neither OPTION_IAPREFIX or OPTION_STATUS_CODE
        while !buf.is_empty() {
            let opt = DhcpV6Option::parse(&mut buf)?;
            match opt {
                DhcpV6Option::StatusCode(v) => ret.status = Some(v),
                DhcpV6Option::IAPrefix(v) => ret.prefix = Some(v),
                _ => {
                    return Err(DhcpError::new(
                        ErrorKind::InvalidDhcpMessage,
                        format!(
                            "Expecting OPTION_IAPREFIX or OPTION_STATUS_CODE \
                             in OPTION_IA_PD option field, but got {}",
                            opt.code()
                        ),
                    ));
                }
            }
        }
        Ok(ret)
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        let mut value_buf = BufferMut::new();
        value_buf.write_u32_be(self.iaid);
        value_buf.write_u32_be(self.t1_sec);
        value_buf.write_u32_be(self.t2_sec);
        if let Some(prefix) = self.prefix.as_ref() {
            prefix.emit(&mut value_buf);
        }
        if let Some(status) = self.status.as_ref() {
            status.emit(&mut value_buf);
        }

        buf.write_u16_be(DhcpV6OptionCode::IAPD.into());
        buf.write_u16_be(value_buf.len() as u16);
        buf.write_bytes(&value_buf.data);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct DhcpV6OptionIaAddr {
    pub address: Ipv6Addr,
    pub preferred_time_sec: u32,
    pub valid_time_sec: u32,
    pub status: Option<DhcpV6OptionStatus>,
}

impl Default for DhcpV6OptionIaAddr {
    fn default() -> Self {
        Self {
            address: Ipv6Addr::UNSPECIFIED,
            preferred_time_sec: 0,
            valid_time_sec: 0,
            status: None,
        }
    }
}

impl DhcpV6OptionIaAddr {
    pub fn new(
        address: Ipv6Addr,
        preferred_time_sec: u32,
        valid_time_sec: u32,
    ) -> Self {
        Self {
            address,
            preferred_time_sec,
            valid_time_sec,
            ..Default::default()
        }
    }

    pub(crate) const fn code() -> DhcpV6OptionCode {
        DhcpV6OptionCode::IAAddr
    }

    // RFC 8415: If the Status Code option (see Section 21.13) does not appear
    // in a message in which the option could appear, the status of the message
    // is assumed to be Success.
    pub(crate) fn is_success(&self) -> bool {
        if let Some(s) = self.status.as_ref() {
            s.is_success()
        } else {
            true
        }
    }

    pub(crate) fn parse(buf: &mut Buffer) -> Result<Self, DhcpError> {
        let code = buf.get_u16_be().context("Invalid DHCPv6 option code")?;
        if code != Self::code().into() {
            return Err(DhcpError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Expecting DHCPv6 option {} code {}, got {}",
                    Self::code(),
                    u16::from(Self::code()),
                    code
                ),
            ));
        }
        let len = buf.get_u16_be().context("Invalid DHCPv6 option len")?;
        let raw = buf
            .get_bytes(len.into())
            .context("Invalid DHCPv6 option OPTION_IAADDR")?;
        let mut buf = Buffer::new(raw);
        Ok(Self {
            address: buf
                .get_ipv6()
                .context("Invalid DHCPv6 option OPTION_IAADDR address")?,
            preferred_time_sec: buf.get_u32_be().context(
                "Invalid DHCPv6 option OPTION_IAADDR preferred time",
            )?,
            valid_time_sec: buf
                .get_u32_be()
                .context("Invalid DHCPv6 option OPTION_IAADDR valid time")?,
            status: {
                if buf.is_empty() {
                    None
                } else {
                    Some(DhcpV6OptionStatus::parse(&mut buf)?)
                }
            },
        })
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        let mut value_buf = BufferMut::new();
        value_buf.write_ipv6(self.address);
        value_buf.write_u32_be(self.preferred_time_sec);
        value_buf.write_u32_be(self.valid_time_sec);
        if let Some(status) = self.status.as_ref() {
            status.emit(&mut value_buf);
        }

        buf.write_u16_be(DhcpV6OptionCode::IAAddr.into());
        buf.write_u16_be(value_buf.len() as u16);
        buf.write_bytes(&value_buf.data);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct DhcpV6OptionIaPrefix {
    pub preferred_time_sec: u32,
    pub valid_time_sec: u32,
    pub prefix_len: u8,
    pub prefix: Ipv6Addr,
    pub status: Option<DhcpV6OptionStatus>,
}

impl Default for DhcpV6OptionIaPrefix {
    fn default() -> Self {
        Self {
            preferred_time_sec: 0,
            valid_time_sec: 0,
            prefix_len: 0,
            prefix: Ipv6Addr::UNSPECIFIED,
            status: None,
        }
    }
}

impl DhcpV6OptionIaPrefix {
    pub fn new(
        prefix: Ipv6Addr,
        prefix_len: u8,
        preferred_time_sec: u32,
        valid_time_sec: u32,
    ) -> Self {
        Self {
            preferred_time_sec,
            valid_time_sec,
            prefix_len,
            prefix,
            status: None,
        }
    }

    pub(crate) fn is_success(&self) -> bool {
        if let Some(s) = self.status.as_ref() {
            s.is_success()
        } else {
            true
        }
    }

    pub(crate) const fn code() -> DhcpV6OptionCode {
        DhcpV6OptionCode::IAPrefix
    }

    pub(crate) fn parse(buf: &mut Buffer) -> Result<Self, DhcpError> {
        let code = buf
            .get_u16_be()
            .context("Invalid DHCPv6 option OPTION_IAPREFIX code")?;
        if code != DhcpV6OptionCode::IAPrefix.into() {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!(
                    "Expecting DHCPv6 option {} code {}, got {}",
                    Self::code(),
                    u16::from(Self::code()),
                    code
                ),
            ));
        }
        let len = buf
            .get_u16_be()
            .context("Invalid DHCPv6 option OPTION_IAPREFIX length")?;
        let raw = buf
            .get_bytes(len.into())
            .context("Invalid DHCPv6 option OPTION_IA_NA")?;
        let mut buf = Buffer::new(raw);
        Ok(Self {
            preferred_time_sec: buf.get_u32_be().context(
                "Invalid DHCPv6 option OPTION_IAPREFIX preferred time",
            )?,
            valid_time_sec: buf
                .get_u32_be()
                .context("Invalid DHCPv6 option OPTION_IAPREFIX valid time")?,
            prefix_len: buf.get_u8().context(
                "Invalid DHCPv6 option OPTION_IAPREFIX prefix length",
            )?,
            prefix: buf
                .get_ipv6()
                .context("Invalid DHCPv6 option OPTION_IAPREFIX address")?,
            status: {
                if buf.is_empty() {
                    None
                } else {
                    Some(DhcpV6OptionStatus::parse(&mut buf)?)
                }
            },
        })
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        let mut value_buf = BufferMut::new();
        value_buf.write_u32_be(self.preferred_time_sec);
        value_buf.write_u32_be(self.valid_time_sec);
        value_buf.write_u8(self.prefix_len);
        value_buf.write_ipv6(self.prefix);
        if let Some(status) = self.status.as_ref() {
            status.emit(&mut value_buf);
        }

        buf.write_u16_be(DhcpV6OptionCode::IAPrefix.into());
        buf.write_u16_be(value_buf.len() as u16);
        buf.write_bytes(&value_buf.data);
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use crate::DhcpV6OptionStatusCode;

    #[test]
    fn parse_iana() -> Result<(), DhcpError> {
        let raw = &[
            0x00, 0x03, 0x00, 0x28, 0xfd, 0x2a, 0xbc, 0x8e, 0x00, 0x00, 0x00,
            0x3c, 0x00, 0x00, 0x00, 0x69, 0x00, 0x05, 0x00, 0x18, 0x20, 0x01,
            0x0d, 0xb8, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x07, 0x6d, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x78,
        ];
        let mut buf = Buffer::new(raw.as_slice());

        let opt = DhcpV6Option::parse(&mut buf)?;

        assert_eq!(
            opt,
            DhcpV6Option::IANA(DhcpV6OptionIaNa {
                iaid: 0xfd2abc8e,
                t1_sec: 60,
                t2_sec: 105,
                address: Some(DhcpV6OptionIaAddr {
                    preferred_time_sec: 120,
                    valid_time_sec: 120,
                    address: Ipv6Addr::from_str("2001:db8:a::76d").unwrap(),
                    status: None,
                }),
                status: None,
            })
        );

        let mut buf = BufferMut::new();
        opt.emit(&mut buf);

        assert_eq!(buf.data.as_slice(), raw);
        Ok(())
    }

    #[test]
    fn parse_pd_msg() -> Result<(), DhcpError> {
        let raw = &[
            0x00, 0x19, 0x00, 0x36, 0x32, 0xaa, 0xbe, 0x4e, 0x00, 0x00, 0xa8,
            0xc0, 0x00, 0x01, 0x0e, 0x00, 0x00, 0x1a, 0x00, 0x19, 0x00, 0x01,
            0x51, 0x80, 0x00, 0x01, 0x51, 0x80, 0x3c, 0x24, 0x0e, 0x03, 0x9c,
            0x0e, 0x29, 0xdb, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x0d, 0x00, 0x09, 0x00, 0x00, 0x53, 0x55, 0x43, 0x43,
            0x45, 0x53, 0x53,
        ];

        let mut buf = Buffer::new(raw);

        let opt = DhcpV6Option::parse(&mut buf)?;

        assert_eq!(
            opt,
            DhcpV6Option::IAPD(DhcpV6OptionIaPd {
                iaid: 0x32aabe4e,
                t1_sec: 43200,
                t2_sec: 69120,
                prefix: Some(DhcpV6OptionIaPrefix {
                    preferred_time_sec: 86400,
                    valid_time_sec: 86400,
                    prefix_len: 60,
                    prefix: Ipv6Addr::from_str("240e:39c:e29:dbf0::").unwrap(),
                    status: None,
                }),
                status: Some(DhcpV6OptionStatus {
                    status: DhcpV6OptionStatusCode::Success,
                    message: "SUCCESS".into(),
                })
            })
        );

        let mut buf = BufferMut::new();
        opt.emit(&mut buf);

        assert_eq!(buf.data.as_slice(), raw);
        Ok(())
    }

    #[test]
    fn parse_pd_no_address() -> Result<(), DhcpError> {
        let raw = &[
            0x00, 0x19, 0x00, 0x1f, 0xc1, 0xdb, 0x20, 0x5c, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x0f, 0x00, 0x06,
            0x4e, 0x4f, 0x50, 0x52, 0x45, 0x46, 0x49, 0x58, 0x41, 0x56, 0x41,
            0x49, 0x4c,
        ];

        let mut buf = Buffer::new(raw);

        let opt = DhcpV6Option::parse(&mut buf)?;

        assert_eq!(
            opt,
            DhcpV6Option::IAPD(DhcpV6OptionIaPd {
                iaid: 0xc1db205c,
                t1_sec: 0,
                t2_sec: 0,
                prefix: None,
                status: Some(DhcpV6OptionStatus {
                    status: DhcpV6OptionStatusCode::NoPrefixAvail,
                    message: "NOPREFIXAVAIL".into(),
                })
            })
        );

        let mut buf = BufferMut::new();
        opt.emit(&mut buf);

        assert_eq!(buf.data.as_slice(), raw);

        Ok(())
    }
}
