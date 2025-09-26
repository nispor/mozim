// SPDX-License-Identifier: Apache-2.0

use std::{
    net::Ipv6Addr,
    time::{Duration, SystemTime},
};

use crate::{
    netlink::{get_iface_index, get_iface_index_mac, get_link_local_addr},
    DhcpError, ErrorKind, ETH_ALEN,
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

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DhcpV6Mode {
    /// Request statefull assignment of one or more IPv6 addresses and/or IPv6
    /// prefixes.
    Statefull(DhcpV6IaType),
    /// As describe in RFC 3736, request stateless configuration options from
    /// DHCPv6 server. The node must have obtained its IPv6 addresses through
    /// some other mechanism(e.g. SLAAC).
    Stateless,
}

impl Default for DhcpV6Mode {
    fn default() -> Self {
        Self::Statefull(DhcpV6IaType::default())
    }
}

impl DhcpV6Mode {
    pub fn new_non_temp_addr() -> Self {
        Self::Statefull(DhcpV6IaType::NonTemporaryAddresses)
    }

    pub fn new_temp_addr() -> Self {
        Self::Statefull(DhcpV6IaType::TemporaryAddresses)
    }

    pub fn new_prefix_delegation() -> Self {
        Self::Statefull(DhcpV6IaType::PrefixDelegation)
    }

    pub fn is_temp_addr(&self) -> bool {
        matches!(self, Self::Statefull(DhcpV6IaType::TemporaryAddresses))
    }
}

impl std::fmt::Display for DhcpV6Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Statefull(s) => write!(f, "statefull-{s}"),
            Self::Stateless => write!(f, "stateless"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash, Default)]
#[non_exhaustive]
pub enum DhcpV6IaType {
    #[default]
    NonTemporaryAddresses,
    TemporaryAddresses,
    PrefixDelegation,
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
    pub iface_name: String,
    pub iface_index: u32,
    pub duid: DhcpV6Duid,
    pub mode: DhcpV6Mode,
    pub src_ip: Ipv6Addr,
    // TODO: Inifniband has 128 bits MAC address.
    pub(crate) src_mac: Option<[u8; ETH_ALEN]>,
    /// Timeout in seconds for getting/refreshing lease.
    /// 0 means infinitely.
    /// By default is wait infinitely.
    pub timeout_sec: u32,
}

impl Default for DhcpV6Config {
    fn default() -> Self {
        Self {
            iface_name: String::new(),
            iface_index: 0,
            duid: DhcpV6Duid::Other(Vec::new()),
            mode: DhcpV6Mode::default(),
            src_ip: Ipv6Addr::UNSPECIFIED,
            src_mac: None,
            timeout_sec: 0,
        }
    }
}

impl DhcpV6Config {
    pub fn new(iface_name: &str, mode: DhcpV6Mode) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            mode,
            ..Default::default()
        }
    }

    pub(crate) fn need_resolve(&self) -> bool {
        self.iface_index == 0 || self.src_ip.is_unspecified()
    }

    /// Get interface MAC address, IPv6 link-local address and interface index.
    pub(crate) async fn resolve(&mut self) -> Result<(), DhcpError> {
        self.iface_index = get_iface_index(&self.iface_name).await?;

        if let Ok((_, src_mac)) = get_iface_index_mac(&self.iface_name).await {
            if src_mac.len() == ETH_ALEN {
                let mut tmp_src_mac = [0u8; ETH_ALEN];
                tmp_src_mac.copy_from_slice(&src_mac[..ETH_ALEN]);
                self.src_mac = Some(tmp_src_mac);
            }
        }

        self.src_ip = get_link_local_addr(self.iface_index).await?;
        self.get_duid_or_init();
        Ok(())
    }

    pub fn set_iface_index(&mut self, iface_index: u32) -> &mut Self {
        self.iface_index = iface_index;
        self
    }

    /// Set the link local IP address
    pub fn set_link_local_ip(&mut self, addr: Ipv6Addr) -> &mut Self {
        self.src_ip = addr;
        self
    }

    /// Set arbitrary DUID
    pub fn set_duid(&mut self, duid: DhcpV6Duid) -> &mut Self {
        self.duid = duid;
        self
    }

    /// Use MAC address of interface to setup DUID to `DhcpV6Duid::LL`.
    pub async fn set_duid_by_iface_mac(
        &mut self,
    ) -> Result<&mut Self, DhcpError> {
        self.duid = if let Some(mac) = self.src_mac.as_ref() {
            DhcpV6Duid::LL(DhcpV6DuidLl::new(ARP_HW_TYPE_ETHERNET, mac))
        } else if let Ok((_, src_mac)) =
            get_iface_index_mac(&self.iface_name).await
        {
            DhcpV6Duid::LL(DhcpV6DuidLl::new(ARP_HW_TYPE_ETHERNET, &src_mac))
        } else {
            return Err(DhcpError::new(
                ErrorKind::NotSupported,
                format!(
                    "Failed to get MAC address of interface {}",
                    self.iface_name
                ),
            ));
        };
        Ok(self)
    }

    /// Get DUID or initialize to DhcpV6Duid::LL() when found MAC address of
    /// specified interface, fallback to `DhcpV6Duid::default()` if no MAC
    /// address.
    pub fn get_duid_or_init(&mut self) -> &DhcpV6Duid {
        if self.duid.is_empty() {
            self.duid = if let Some(mac) = self.src_mac.as_ref() {
                DhcpV6Duid::LL(DhcpV6DuidLl::new(ARP_HW_TYPE_ETHERNET, mac))
            } else {
                DhcpV6Duid::default()
            };
        }
        &self.duid
    }

    /// Timeout in seconds for getting/refreshing lease.
    /// 0 means infinitely.
    /// By default is wait infinitely.
    pub fn set_timeout_sec(&mut self, timeout_sec: u32) -> &mut Self {
        self.timeout_sec = timeout_sec;
        self
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum DhcpV6Duid {
    /// DUID Based on Link-Layer Address Plus Time
    LLT(DhcpV6DuidLlt),
    /// DUID Assigned by Vendor Based on Enterprise Number
    EN(DhcpV6DuidEn),
    /// DUID Based on Link-Layer Address
    LL(DhcpV6DuidLl),
    /// DUID Based on Universally Unique Identifier
    UUID(DhcpV6DuidUuid),
    /// Userdefined DUID
    Other(Vec<u8>),
}

impl Default for DhcpV6Duid {
    fn default() -> Self {
        let mut rand_data = [0u8; 16];
        rand::fill(&mut rand_data);
        Self::Other(rand_data.to_vec())
    }
}

impl DhcpV6Duid {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::LLT(v) => v.to_vec(),
            Self::EN(v) => v.to_vec(),
            Self::LL(v) => v.to_vec(),
            Self::UUID(v) => v.to_vec(),
            Self::Other(v) => v.clone(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self == &Self::Other(Vec::new())
    }
}

// Type 1
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct DhcpV6DuidLlt {
    pub hardware_type: u16,
    pub time: u32,
    pub link_layer_address: Vec<u8>,
}

impl DhcpV6DuidLlt {
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
pub struct DhcpV6DuidEn {
    pub enterprise_number: u32,
    pub identifier: Vec<u8>,
}

impl DhcpV6DuidEn {
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
pub struct DhcpV6DuidLl {
    hardware_type: u16,
    link_layer_address: Vec<u8>,
}

impl DhcpV6DuidLl {
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
pub struct DhcpV6DuidUuid {
    uuid: u128,
}

impl DhcpV6DuidUuid {
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
