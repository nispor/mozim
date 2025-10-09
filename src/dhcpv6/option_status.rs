// SPDX-License-Identifier: Apache-2.0

use crate::{
    Buffer, BufferMut, DhcpError, DhcpV6OptionCode, ErrorContext, ErrorKind,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DhcpV6OptionStatus {
    pub status: DhcpV6OptionStatusCode,
    pub message: String,
}

impl DhcpV6OptionStatus {
    pub(crate) fn is_success(&self) -> bool {
        self.status == DhcpV6OptionStatusCode::Success
    }

    pub(crate) const fn code() -> DhcpV6OptionCode {
        DhcpV6OptionCode::StatusCode
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
        let len: usize = buf
            .get_u16_be()
            .context("Invalid DHCPv6 option len")?
            .into();
        let raw = buf
            .get_bytes(len)
            .context("Invalid DHCPv6 option OPTION_STATUS_CODE")?;
        let mut buf = Buffer::new(raw);

        Ok(Self {
            status: buf
                .get_u16_be()
                .context(
                    "Invalid DHCPv6 option OPTION_STATUS_CODE status-code",
                )?
                .into(),
            message: buf
                .get_string_without_null(len - 2)
                .context("Invalid DHCPv6 option OPTION_STATUS_CODE message")?,
        })
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        buf.write_u16_be(DhcpV6OptionCode::StatusCode.into());
        buf.write_u16_be((self.message.len() + 2) as u16);
        buf.write_u16_be(self.status.into());
        buf.write_string_without_null(&self.message);
    }
}

const STATUS_CODE_SUCCESS: u16 = 0;
const STATUS_CODE_UNSPEC_FAIL: u16 = 1;
const STATUS_CODE_NO_ADDRS_AVAIL: u16 = 2;
const STATUS_CODE_NO_BINDING: u16 = 3;
const STATUS_CODE_NOT_ON_LINK: u16 = 4;
const STATUS_CODE_USE_MULTICAST: u16 = 5;
const STATUS_CODE_NO_PREFIX_AVAIL: u16 = 6;

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
pub enum DhcpV6OptionStatusCode {
    Success,
    UnspecFail,
    NoAddrsAvail,
    NoBinding,
    NotOnLink,
    UseMulticast,
    NoPrefixAvail,
    Other(u16),
}

impl std::fmt::Display for DhcpV6OptionStatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::UnspecFail => write!(f, "unspec_fail"),
            Self::NoAddrsAvail => write!(f, "no_addrs_avail"),
            Self::NoBinding => write!(f, "no_binding"),
            Self::NotOnLink => write!(f, "not_on_link"),
            Self::UseMulticast => write!(f, "use_multicast"),
            Self::NoPrefixAvail => write!(f, "no_prefix_avail"),
            Self::Other(d) => write!(f, "other({d})"),
        }
    }
}

impl From<DhcpV6OptionStatusCode> for u16 {
    fn from(v: DhcpV6OptionStatusCode) -> u16 {
        match v {
            DhcpV6OptionStatusCode::Success => STATUS_CODE_SUCCESS,
            DhcpV6OptionStatusCode::UnspecFail => STATUS_CODE_UNSPEC_FAIL,
            DhcpV6OptionStatusCode::NoAddrsAvail => STATUS_CODE_NO_ADDRS_AVAIL,
            DhcpV6OptionStatusCode::NoBinding => STATUS_CODE_NO_BINDING,
            DhcpV6OptionStatusCode::NotOnLink => STATUS_CODE_NOT_ON_LINK,
            DhcpV6OptionStatusCode::UseMulticast => STATUS_CODE_USE_MULTICAST,
            DhcpV6OptionStatusCode::NoPrefixAvail => {
                STATUS_CODE_NO_PREFIX_AVAIL
            }
            DhcpV6OptionStatusCode::Other(d) => d,
        }
    }
}

impl From<u16> for DhcpV6OptionStatusCode {
    fn from(d: u16) -> Self {
        match d {
            STATUS_CODE_SUCCESS => DhcpV6OptionStatusCode::Success,
            STATUS_CODE_UNSPEC_FAIL => DhcpV6OptionStatusCode::UnspecFail,
            STATUS_CODE_NO_ADDRS_AVAIL => DhcpV6OptionStatusCode::NoAddrsAvail,
            STATUS_CODE_NO_BINDING => DhcpV6OptionStatusCode::NoBinding,
            STATUS_CODE_NOT_ON_LINK => DhcpV6OptionStatusCode::NotOnLink,
            STATUS_CODE_USE_MULTICAST => DhcpV6OptionStatusCode::UseMulticast,
            STATUS_CODE_NO_PREFIX_AVAIL => {
                DhcpV6OptionStatusCode::NoPrefixAvail
            }
            _ => DhcpV6OptionStatusCode::Other(d),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::DhcpV6Option;

    #[test]
    fn parse_status_no_addr_avail() -> Result<(), DhcpError> {
        let raw = &[
            0x00, 0x0d, 0x00, 0x18, 0x00, 0x02, 0x6e, 0x6f, 0x20, 0x61, 0x64,
            0x64, 0x72, 0x65, 0x73, 0x73, 0x65, 0x73, 0x20, 0x61, 0x76, 0x61,
            0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65,
        ];

        let mut buf = Buffer::new(raw);

        let opt = DhcpV6Option::parse(&mut buf)?;

        assert_eq!(
            opt,
            DhcpV6Option::StatusCode(DhcpV6OptionStatus {
                status: DhcpV6OptionStatusCode::NoAddrsAvail,
                message: "no addresses available".into(),
            })
        );

        let mut buf = BufferMut::new();
        opt.emit(&mut buf);

        assert_eq!(buf.data.as_slice(), raw);
        Ok(())
    }
}
