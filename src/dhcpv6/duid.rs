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
        // Instead of directly modify input buffer, we limit the data range to
        // option length.
        let raw = buf.get_bytes(len).context("Invalid DHCPv6 DUID")?;
        let mut buf = Buffer::new(raw);
        let id_type = buf.get_u16_be().context("Invalid DHCPv6 DUID type")?;
        // RFC 8415, 11. DHCP Unique Identifier (DUID)
        //   Clients and servers MUST treat DUIDs as opaque values and MUST only
        //   compare DUIDs for equality.  Clients and servers SHOULD NOT in any
        // other   way interpret DUIDs.
        //
        // Hence we do not raise parsing error here but fallback to treat
        // DUID as opaque byte array.
        Ok(match id_type {
            DUID_TYPE_LLT => {
                match DhcpV6DuidLinkLayerAddrPlusTime::parse(&mut buf, len) {
                    Ok(v) => Self::LinkLayerAddressPlusTime(v),
                    Err(_) => Self::Raw(raw.to_vec()),
                }
            }
            DUID_TYPE_EN => {
                match DhcpV6DuidEnterpriseNumber::parse(&mut buf, len) {
                    Ok(v) => Self::EnterpriseNumber(v),
                    Err(_) => Self::Raw(raw.to_vec()),
                }
            }
            DUID_TYPE_LL => match DhcpV6DuidLinkLayerAddr::parse(&mut buf, len)
            {
                Ok(v) => Self::LinkLayerAddress(v),
                Err(_) => Self::Raw(raw.to_vec()),
            },
            DUID_TYPE_UUID => match DhcpV6DuidUuid::parse(&mut buf, len) {
                Ok(v) => Self::UUID(v),
                Err(_) => Self::Raw(raw.to_vec()),
            },
            _ => Self::Raw(raw.to_vec()),
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

    pub(crate) fn parse(
        buf: &mut Buffer,
        len: usize,
    ) -> Result<Self, DhcpError> {
        Ok(Self {
            hardware_type: buf
                .get_u16_be()
                .context("Invalid DHCPv6 DUID LLT hardware type")?,
            time: buf.get_u32_be().context("Invalid DHCPv6 DUID LLT time")?,
            link_layer_address: buf
                .get_bytes(len - 8)
                .context("Invalid DHCPv6 DUID LLT link layer address")?
                .to_vec(),
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

    pub(crate) fn parse(
        buf: &mut Buffer,
        len: usize,
    ) -> Result<Self, DhcpError> {
        Ok(Self {
            enterprise_number: buf
                .get_u32_be()
                .context("Invalid DHCPv6 DUID EN enterprise number")?,
            identifier: buf
                .get_bytes(len - 6)
                .context("Invalid DHCPv6 DUID EN identifier")?
                .to_vec(),
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

    pub(crate) fn parse(
        buf: &mut Buffer,
        len: usize,
    ) -> Result<Self, DhcpError> {
        Ok(Self {
            hardware_type: buf
                .get_u16_be()
                .context("Invalid DHCPv6 DUID LL hardware type")?,
            link_layer_address: buf
                .get_bytes(len - 4)
                .context("Invalid DHCPv6 DUID LL link layer address")?
                .to_vec(),
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

    pub(crate) fn parse(
        buf: &mut Buffer,
        len: usize,
    ) -> Result<Self, DhcpError> {
        if len != 16 {
            // Still need to consume the buffer in case caller decided to move
            // even with error
            buf.get_bytes(len).ok();
            Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!(
                    "Invalid DHCPv6 DUID UUID, expecting 16 bytes, got {len} \
                     bytes"
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
