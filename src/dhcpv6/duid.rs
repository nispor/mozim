// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, SystemTime};

use crate::{
    buffer::{Buffer, BufferMut},
    DhcpError, ErrorContext, ErrorKind,
};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum DhcpV6Duid {
    /// DUID Based on Link-Layer Address Plus Time
    LinkLayerAddressPlusTime(DhcpV6DuidLinkLayerAddrPlusTime),
    /// DUID Assigned by Vendor Based on Enterprise Number
    EnterpriseNumber(DhcpV6DuidEnterpriseNumber),
    /// DUID Based on Link-Layer Address
    LinkLayerAddress(DhcpV6DuidLinkLayerAddr),
    /// DUID Based on Universally Unique Identifier
    UUID(DhcpV6DuidUuid),
    /// Opaque byte array
    Raw(Vec<u8>),
}

impl Default for DhcpV6Duid {
    fn default() -> Self {
        let mut rand_data = [0u8; 16];
        rand::fill(&mut rand_data);
        rand_data[0] = 0;
        rand_data[1] = 255;
        Self::Raw(rand_data.to_vec())
    }
}

const DUID_TYPE_LLT: u16 = 1;
const DUID_TYPE_EN: u16 = 2;
const DUID_TYPE_LL: u16 = 3;
const DUID_TYPE_UUID: u16 = 4;

impl DhcpV6Duid {
    pub(crate) fn parse(
        buf: &mut Buffer,
        len: usize,
    ) -> Result<Self, DhcpError> {
        let raw = buf.peek_bytes(len).context("Invalid DHCPv6 DUID")?.to_vec();
        let id_type = buf.peek_u16_be().context("Invalid DHCPv6 DUID type")?;
        // RFC 8415, 11. DHCP Unique Identifier (DUID)
        //   Clients and servers MUST treat DUIDs as opaque values and MUST only
        //   compare DUIDs for equality.  Clients and servers SHOULD NOT in any
        // other   way interpret DUIDs.
        //
        // Hence we do not raise parsing error here but fallback to treat
        // DUID as opaque byte array.
        Ok(match id_type {
            DUID_TYPE_LLT => {
                match DhcpV6DuidLinkLayerAddrPlusTime::parse(buf) {
                    Ok(v) => Self::LinkLayerAddressPlusTime(v),
                    Err(_) => Self::Raw(raw),
                }
            }
            DUID_TYPE_EN => match DhcpV6DuidEnterpriseNumber::parse(buf) {
                Ok(v) => Self::EnterpriseNumber(v),
                Err(_) => Self::Raw(raw),
            },
            DUID_TYPE_LL => match DhcpV6DuidLinkLayerAddr::parse(buf) {
                Ok(v) => Self::LinkLayerAddress(v),
                Err(_) => Self::Raw(raw),
            },
            DUID_TYPE_UUID => match DhcpV6DuidUuid::parse(buf) {
                Ok(v) => Self::UUID(v),
                Err(_) => Self::Raw(raw),
            },
            _ => Self::Raw(raw),
        })
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        match self {
            Self::LinkLayerAddressPlusTime(v) => v.emit(buf),
            Self::EnterpriseNumber(v) => v.emit(buf),
            Self::LinkLayerAddress(v) => v.emit(buf),
            Self::UUID(v) => v.emit(buf),
            Self::Raw(v) => buf.write_bytes(v.as_slice()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self == &Self::Raw(Vec::new())
    }
}

// RFC 8415 11.2.  DUID Based on Link-Layer Address Plus Time (DUID-LLT)
// Indicate the base time is midnight (UTC), January 1, 2000
// This is calculated value by chrono:
//         chrono::Utc.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap()
//       - chrono::Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap()
const BASE_TIME: Duration = Duration::new(946684800, 0);

// Type 1
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct DhcpV6DuidLinkLayerAddrPlusTime {
    pub hardware_type: u16,
    /// Seconds since UTC midnight 2000 January 1, modulo 2^32
    pub time: u32,
    pub link_layer_address: Vec<u8>,
}

impl DhcpV6DuidLinkLayerAddrPlusTime {
    pub fn new(hardware_type: u16, link_layer_address: &[u8]) -> Self {
        let time: u32 = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|s| s.checked_sub(BASE_TIME))
            .map(|t| t.as_secs())
            .map(|t| t as u32)
            .unwrap_or_default();

        Self {
            hardware_type,
            time,
            link_layer_address: link_layer_address.to_vec(),
        }
    }

    pub(crate) fn parse(buf: &mut Buffer) -> Result<Self, DhcpError> {
        let subtype = buf
            .get_u16_be()
            .context("Invalid DHCPv6 DUID LLT subtype")?;
        if subtype != DUID_TYPE_LLT {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!(
                    "Invalid DHCPv6 DUID LLT subtype, expecting \
                     {DUID_TYPE_LLT}, got {subtype}"
                ),
            ));
        }
        Ok(Self {
            hardware_type: buf
                .get_u16_be()
                .context("Invalid DHCPv6 DUID LLT hardware type")?,
            time: buf.get_u32_be().context("Invalid DHCPv6 DUID LLT time")?,
            link_layer_address: buf.get_remains().to_vec(),
        })
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        buf.write_u16_be(DUID_TYPE_LLT);
        buf.write_u16_be(self.hardware_type);
        buf.write_u32_be(self.time);
        buf.write_bytes(self.link_layer_address.as_slice());
    }
}

// Type 2
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct DhcpV6DuidEnterpriseNumber {
    pub enterprise_number: u32,
    pub identifier: Vec<u8>,
}

impl DhcpV6DuidEnterpriseNumber {
    pub fn new(enterprise_number: u32, identifier: &[u8]) -> Self {
        Self {
            enterprise_number,
            identifier: identifier.to_vec(),
        }
    }

    pub(crate) fn parse(buf: &mut Buffer) -> Result<Self, DhcpError> {
        let subtype =
            buf.get_u16_be().context("Invalid DHCPv6 DUID EN subtype")?;
        if subtype != DUID_TYPE_EN {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!(
                    "Invalid DHCPv6 DUID EN subtype, expecting \
                     {DUID_TYPE_EN}, got {subtype}"
                ),
            ));
        }
        Ok(Self {
            enterprise_number: buf
                .get_u32_be()
                .context("Invalid DHCPv6 DUID EN enterprise number")?,
            identifier: buf.get_remains().to_vec(),
        })
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        buf.write_u16_be(DUID_TYPE_EN);
        buf.write_u32_be(self.enterprise_number);
        buf.write_bytes(self.identifier.as_slice());
    }
}

// Type 3
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct DhcpV6DuidLinkLayerAddr {
    hardware_type: u16,
    link_layer_address: Vec<u8>,
}

impl DhcpV6DuidLinkLayerAddr {
    pub fn new(hardware_type: u16, link_layer_address: &[u8]) -> Self {
        Self {
            hardware_type,
            link_layer_address: link_layer_address.to_vec(),
        }
    }

    pub(crate) fn parse(buf: &mut Buffer) -> Result<Self, DhcpError> {
        let subtype =
            buf.get_u16_be().context("Invalid DHCPv6 DUID LL subtype")?;
        if subtype != DUID_TYPE_LL {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!(
                    "Invalid DHCPv6 DUID LL subtype, expecting \
                     {DUID_TYPE_LL}, got {subtype}"
                ),
            ));
        }
        Ok(Self {
            hardware_type: buf
                .get_u16_be()
                .context("Invalid DHCPv6 DUID LL hardware type")?,
            link_layer_address: buf.get_remains().to_vec(),
        })
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        buf.write_u16_be(DUID_TYPE_LL);
        buf.write_u16_be(self.hardware_type);
        buf.write_bytes(self.link_layer_address.as_slice());
    }
}

// Type 4
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub struct DhcpV6DuidUuid {
    uuid: u128,
}

impl DhcpV6DuidUuid {
    pub fn new(uuid: u128) -> Self {
        Self { uuid }
    }

    pub(crate) fn parse(buf: &mut Buffer) -> Result<Self, DhcpError> {
        let subtype = buf
            .get_u16_be()
            .context("Invalid DHCPv6 DUID UUID subtype")?;
        if subtype != DUID_TYPE_UUID {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!(
                    "Invalid DHCPv6 DUID UUID subtype, expecting \
                     {DUID_TYPE_UUID}, got {subtype}"
                ),
            ));
        }
        if buf.remain_len() != 16 {
            Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!(
                    "Invalid DHCPv6 DUID UUID, expecting 16 bytes, got {} \
                     bytes",
                    buf.remain_len()
                ),
            ))
        } else {
            Ok(Self {
                uuid: buf.get_u128_be().context("Invalid DHCPv6 DUID UUID")?,
            })
        }
    }

    pub(crate) fn emit(&self, buf: &mut BufferMut) {
        buf.write_u16_be(DUID_TYPE_UUID);
        buf.write_u128_be(self.uuid);
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::DhcpV6Option;

    #[test]
    fn parse_srv_duid_llt() -> Result<(), DhcpError> {
        let raw: &[u8] = &[
            0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x30, 0x7a, 0x70,
            0xb8, 0x72, 0x07, 0x26, 0xd9, 0x99, 0xd9,
        ];
        let duid = DhcpV6Option::parse(&mut Buffer::new(raw))?;

        assert_eq!(
            duid,
            DhcpV6Option::ServerId(DhcpV6Duid::LinkLayerAddressPlusTime(
                DhcpV6DuidLinkLayerAddrPlusTime {
                    hardware_type: 1,
                    time: 0x307a70b8,
                    link_layer_address: vec![
                        0x72, 0x07, 0x26, 0xd9, 0x99, 0xd9
                    ],
                }
            ))
        );
        let mut buf = BufferMut::new();
        duid.emit(&mut buf);

        assert_eq!(buf.data.as_slice(), raw);
        Ok(())
    }

    #[test]
    fn parse_cli_duid_ll() -> Result<(), DhcpError> {
        let raw: &[u8] = &[
            0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0xd2, 0xfd, 0xf9,
            0xb4, 0x48, 0xb7,
        ];
        let duid = DhcpV6Option::parse(&mut Buffer::new(raw))?;

        assert_eq!(
            duid,
            DhcpV6Option::ClientId(DhcpV6Duid::LinkLayerAddress(
                DhcpV6DuidLinkLayerAddr {
                    hardware_type: 1,
                    link_layer_address: vec![
                        0xd2, 0xfd, 0xf9, 0xb4, 0x48, 0xb7
                    ],
                }
            ))
        );

        let mut buf = BufferMut::new();
        duid.emit(&mut buf);

        assert_eq!(buf.data.as_slice(), raw);

        Ok(())
    }

    // TODO: Add test for UUID, but I never able to capture third party DHCP
    // Client or server use UUID. So no trust source yet.
}
