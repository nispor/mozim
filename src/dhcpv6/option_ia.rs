// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv6Addr;

use crate::{
    buffer::{Buffer, BufferMut},
    DhcpError, DhcpV6OptionCode, DhcpV6OptionStatus, ErrorContext, ErrorKind,
};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct DhcpV6OptionIaNa {
    pub iaid: u32,
    pub t1_sec: u32,
    pub t2_sec: u32,
    pub address: DhcpV6OptionIaAddr,
}

impl Default for DhcpV6OptionIaNa {
    fn default() -> Self {
        Self {
            iaid: rand::random(),
            t1_sec: 0,
            t2_sec: 0,
            address: DhcpV6OptionIaAddr::default(),
        }
    }
}

impl DhcpV6OptionIaNa {
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
            address,
        }
    }

    pub(crate) fn parse(
        buf: &mut Buffer,
        len: usize,
    ) -> Result<Self, DhcpError> {
        let raw = buf
            .get_bytes(len)
            .context("Invalid DHCPv6 option OPTION_IA_NA")?;
        let mut buf = Buffer::new(raw);
        Ok(Self {
            iaid: buf
                .get_u32_be()
                .context("Invalid DHCPv6 option OPTION_IA_NA IAID")?,
            t1_sec: buf
                .get_u32_be()
                .context("Invalid DHCPv6 option OPTION_IA_NA T1")?,
            t2_sec: buf
                .get_u32_be()
                .context("Invalid DHCPv6 option OPTION_IA_NA T2")?,
            address: {
                let remain_len = buf.remain_len();
                DhcpV6OptionIaAddr::parse(&mut buf, remain_len)?
            },
        })
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        let mut value_buf = BufferMut::new(16);
        value_buf.write_u32_be(self.iaid);
        value_buf.write_u32_be(self.t1_sec);
        value_buf.write_u32_be(self.t2_sec);
        self.address.emit(&mut value_buf);

        buf.write_u16_be(DhcpV6OptionCode::IANA.into());
        buf.write_u16_be(value_buf.len() as u16);
        buf.write_bytes(&value_buf.data);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct DhcpV6OptionIaTa {
    pub iaid: u32,
    pub address: DhcpV6OptionIaAddr,
}

impl Default for DhcpV6OptionIaTa {
    fn default() -> Self {
        Self {
            iaid: rand::random(),
            address: DhcpV6OptionIaAddr::default(),
        }
    }
}

impl DhcpV6OptionIaTa {
    pub(crate) fn new(iaid: u32, address: DhcpV6OptionIaAddr) -> Self {
        Self { iaid, address }
    }

    pub(crate) fn parse(
        buf: &mut Buffer,
        len: usize,
    ) -> Result<Self, DhcpError> {
        let raw = buf
            .get_bytes(len)
            .context("Invalid DHCPv6 option OPTION_IA_TA")?;
        let mut buf = Buffer::new(raw);
        Ok(Self {
            iaid: buf
                .get_u32_be()
                .context("Invalid DHCPv6 option OPTION_IA_TA IAID")?,
            address: {
                let remain_len = buf.remain_len();
                DhcpV6OptionIaAddr::parse(&mut buf, remain_len)?
            },
        })
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        let mut value_buf = BufferMut::new(16);
        value_buf.write_u32_be(self.iaid);
        self.address.emit(&mut value_buf);

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
    pub prefix: DhcpV6OptionIaPrefix,
}

impl Default for DhcpV6OptionIaPd {
    fn default() -> Self {
        Self {
            iaid: rand::random(),
            t1_sec: 0,
            t2_sec: 0,
            prefix: DhcpV6OptionIaPrefix::default(),
        }
    }
}

impl DhcpV6OptionIaPd {
    pub(crate) fn new(prefix: Ipv6Addr, prefix_len: u8) -> Self {
        Self {
            prefix: DhcpV6OptionIaPrefix {
                prefix,
                prefix_len,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    pub(crate) fn parse(
        buf: &mut Buffer,
        len: usize,
    ) -> Result<Self, DhcpError> {
        let raw = buf
            .get_bytes(len)
            .context("Invalid DHCPv6 option OPTION_IA_PD")?;
        let mut buf = Buffer::new(raw);
        Ok(Self {
            iaid: buf
                .get_u32_be()
                .context("Invalid DHCPv6 option OPTION_IA_PD IAID")?,
            t1_sec: buf
                .get_u32_be()
                .context("Invalid DHCPv6 option OPTION_IA_PD T1")?,
            t2_sec: buf
                .get_u32_be()
                .context("Invalid DHCPv6 option OPTION_IA_PD T2")?,
            prefix: {
                let remain_len = buf.remain_len();
                DhcpV6OptionIaPrefix::parse(&mut buf, remain_len)?
            },
        })
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        let mut value_buf = BufferMut::new(16);
        value_buf.write_u32_be(self.iaid);
        value_buf.write_u32_be(self.t1_sec);
        value_buf.write_u32_be(self.t2_sec);
        self.prefix.emit(&mut value_buf);

        buf.write_u16_be(DhcpV6OptionCode::IAPD.into());
        buf.write_u16_be(value_buf.len() as u16);
        buf.write_bytes(&value_buf.data);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct DhcpV6OptionIaAddr {
    pub addr: Ipv6Addr,
    pub preferred_time_sec: u32,
    pub valid_time_sec: u32,
    pub status: Option<DhcpV6OptionStatus>,
}

impl Default for DhcpV6OptionIaAddr {
    fn default() -> Self {
        Self {
            addr: Ipv6Addr::UNSPECIFIED,
            preferred_time_sec: 0,
            valid_time_sec: 0,
            status: None,
        }
    }
}

impl DhcpV6OptionIaAddr {
    pub fn new(
        addr: Ipv6Addr,
        preferred_time_sec: u32,
        valid_time_sec: u32,
    ) -> Self {
        Self {
            addr,
            preferred_time_sec,
            valid_time_sec,
            ..Default::default()
        }
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

    pub(crate) fn parse(
        buf: &mut Buffer,
        len: usize,
    ) -> Result<Self, DhcpError> {
        let raw = buf
            .get_bytes(len)
            .context("Invalid DHCPv6 option OPTION_IAADDR")?;
        let mut buf = Buffer::new(raw);
        let code = buf
            .get_u16_be()
            .context("Invalid DHCPv6 option OPTION_IAADDR code")?;
        if code != DhcpV6OptionCode::IAAddr.into() {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!(
                    "Expecting OPTION_IAADDR({}), but got {code}",
                    u16::from(DhcpV6OptionCode::IAAddr)
                ),
            ));
        }
        let _len = buf
            .get_u16_be()
            .context("Invalid DHCPv6 option OPTION_IAADDR length")?;

        Ok(Self {
            addr: buf
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
                    let remain_len = buf.remain_len();
                    Some(DhcpV6OptionStatus::parse(&mut buf, remain_len)?)
                }
            },
        })
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        let mut value_buf = BufferMut::new(16);
        value_buf.write_ipv6(self.addr);
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
    pub(crate) fn is_success(&self) -> bool {
        if let Some(s) = self.status.as_ref() {
            s.is_success()
        } else {
            true
        }
    }

    pub(crate) fn parse(
        buf: &mut Buffer,
        len: usize,
    ) -> Result<Self, DhcpError> {
        let raw = buf
            .get_bytes(len)
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
                    Some({
                        let remain_len = buf.remain_len();
                        DhcpV6OptionStatus::parse(&mut buf, remain_len)?
                    })
                }
            },
        })
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        let mut value_buf = BufferMut::new(16);
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
