// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv6Addr;
use std::time::{Duration, SystemTime};

use rand::RngCore;

use crate::{
    mac::mac_str_to_u8_array,
    nispor::{get_ipv6_addr_of_iface, get_nispor_iface},
    socket::DEFAULT_SOCKET_TIMEOUT,
    DhcpError,
};

// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
const ARP_HW_TYPE_ETHERNET: u16 = 1;

const OPTION_IA_NA: u16 = 3;
const OPTION_IA_TA: u16 = 4;
const OPTION_IA_PD: u16 = 5;

// RFC 8415 11.2.  DUID Based on Link-Layer Address Plus Time (DUID-LLT)
// Indicate the base time is midnight (UTC), January 1, 2000
// This is calculated value by chrono:
//         chrono::Utc.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap()
//       - chrono::Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap()
const BASE_TIME: Duration = Duration::new(946684800, 0);

const DHCPV6_DUID_TYPE_LLT: u16 = 1;
const DHCPV6_DUID_TYPE_EN: u16 = 2;
const DHCPV6_DUID_TYPE_LL: u16 = 3;
const DHCPV6_DUID_TYPE_UUID: u16 = 4;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum DhcpV6IaType {
    NonTemporaryAddresses,
    TemporaryAddresses,
    PrefixDelegation,
}

impl Default for DhcpV6IaType {
    fn default() -> Self {
        Self::NonTemporaryAddresses
    }
}

impl std::fmt::Display for DhcpV6IaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::NonTemporaryAddresses => "IANA",
                Self::TemporaryAddresses => "IATA",
                Self::PrefixDelegation => "IAPD",
            }
        )
    }
}

impl From<DhcpV6IaType> for u16 {
    fn from(v: DhcpV6IaType) -> Self {
        match v {
            DhcpV6IaType::NonTemporaryAddresses => OPTION_IA_NA,
            DhcpV6IaType::TemporaryAddresses => OPTION_IA_TA,
            DhcpV6IaType::PrefixDelegation => OPTION_IA_PD,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct DhcpV6Config {
    pub(crate) iface_name: String,
    pub(crate) iface_index: u32,
    pub(crate) duid: Dhcpv6Duid,
    pub(crate) timeout: u32,
    pub(crate) ia_type: DhcpV6IaType,
    pub(crate) src_ip: Ipv6Addr,
    pub(crate) socket_timeout: u32,
}

impl Default for DhcpV6Config {
    fn default() -> Self {
        Self {
            iface_name: String::new(),
            iface_index: 0,
            duid: Dhcpv6Duid::Other(Vec::new()),
            timeout: 0,
            ia_type: DhcpV6IaType::default(),
            src_ip: Ipv6Addr::UNSPECIFIED,
            socket_timeout: DEFAULT_SOCKET_TIMEOUT,
        }
    }
}

impl DhcpV6Config {
    pub fn new(iface_name: &str, ia_type: DhcpV6IaType) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            ia_type,
            ..Default::default()
        }
    }

    /// Set timeout in seconds
    pub fn set_timeout(&mut self, timeout: u32) -> &mut Self {
        self.timeout = timeout;
        self
    }

    /// Set arbitrary DUID
    pub fn set_duid(&mut self, duid: Dhcpv6Duid) -> &mut Self {
        self.duid = duid;
        self
    }

    // Check whether interface exists and resolve iface_index and MAC
    pub(crate) fn init(&mut self) -> Result<(), DhcpError> {
        let np_iface = get_nispor_iface(self.iface_name.as_str(), true)?;
        self.iface_index = np_iface.index;
        self.src_ip = get_ipv6_addr_of_iface(&np_iface)?;
        self.duid = if np_iface.mac_address.is_empty() {
            Dhcpv6Duid::default()
        } else {
            Dhcpv6Duid::LL(Dhcpv6DuidLl::new(
                ARP_HW_TYPE_ETHERNET,
                &mac_str_to_u8_array(np_iface.mac_address.as_str()),
            ))
        };
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Dhcpv6Duid {
    LLT(Dhcpv6DuidLlt),
    EN(Dhcpv6DuidEn),
    LL(Dhcpv6DuidLl),
    UUID(Dhcpv6DuidUuid),
    Other(Vec<u8>),
}

impl Default for Dhcpv6Duid {
    fn default() -> Self {
        let mut rand_data = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut rand_data);
        Self::Other(rand_data.to_vec())
    }
}

impl Dhcpv6Duid {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::LLT(v) => v.to_vec(),
            Self::EN(v) => v.to_vec(),
            Self::LL(v) => v.to_vec(),
            Self::UUID(v) => v.to_vec(),
            Self::Other(v) => v.clone(),
        }
    }
}

// Type 1
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Dhcpv6DuidLlt {
    pub hardware_type: u16,
    pub time: u32,
    pub link_layer_address: Vec<u8>,
}

impl Dhcpv6DuidLlt {
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

    pub fn to_vec(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        ret.extend_from_slice(&DHCPV6_DUID_TYPE_LLT.to_be_bytes());
        ret.extend_from_slice(&self.hardware_type.to_be_bytes());
        ret.extend_from_slice(&self.time.to_be_bytes());
        ret.extend_from_slice(self.link_layer_address.as_slice());
        ret
    }
}

// Type 2
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Dhcpv6DuidEn {
    pub enterprise_number: u32,
    pub identifier: Vec<u8>,
}

impl Dhcpv6DuidEn {
    pub fn new(enterprise_number: u32, identifier: &[u8]) -> Self {
        Self {
            enterprise_number,
            identifier: identifier.to_vec(),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        ret.extend_from_slice(&DHCPV6_DUID_TYPE_EN.to_be_bytes());
        ret.extend_from_slice(&self.enterprise_number.to_be_bytes());
        ret.extend_from_slice(self.identifier.as_slice());
        ret
    }
}

// Type 3
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Dhcpv6DuidLl {
    hardware_type: u16,
    link_layer_address: Vec<u8>,
}

impl Dhcpv6DuidLl {
    pub fn new(hardware_type: u16, link_layer_address: &[u8]) -> Self {
        Self {
            hardware_type,
            link_layer_address: link_layer_address.to_vec(),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        ret.extend_from_slice(&DHCPV6_DUID_TYPE_LL.to_be_bytes());
        ret.extend_from_slice(&self.hardware_type.to_be_bytes());
        ret.extend_from_slice(self.link_layer_address.as_slice());
        ret
    }
}

// Type 4
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub struct Dhcpv6DuidUuid {
    uuid: u128,
}

impl Dhcpv6DuidUuid {
    pub fn new(uuid: u128) -> Self {
        Self { uuid }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        ret.extend_from_slice(&DHCPV6_DUID_TYPE_UUID.to_be_bytes());
        ret.extend_from_slice(&self.uuid.to_be_bytes());
        ret
    }
}
