// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv6Addr;

use crate::{
    netlink::{get_iface_index, get_iface_index_mac, get_link_local_addr},
    DhcpError, DhcpV6Duid, DhcpV6DuidLinkLayerAddr, DhcpV6OptionCode,
    ErrorKind, ETH_ALEN,
};

// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
const ARP_HW_TYPE_ETHERNET: u16 = 1;

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash, Default)]
#[non_exhaustive]
pub enum DhcpV6IaType {
    #[default]
    NonTemporaryAddresses,
    TemporaryAddresses,
    PrefixDelegation,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash, Default)]
#[non_exhaustive]
pub enum DhcpV6Mode {
    #[default]
    NonTemporaryAddresses,
    TemporaryAddresses,
    /// Request prefix delegation with specified prefix length.
    /// This is just hint for DHCPv6 server, server might reply prefix with
    /// smaller prefix length.
    PrefixDelegation(u8),
    // As describe in RFC 3736, request stateless configuration options from
    // DHCPv6 server. The node must have obtained its IPv6 addresses through
    // some other mechanism(e.g. SLAAC).
    //Stateless,
}

impl std::fmt::Display for DhcpV6Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonTemporaryAddresses => {
                write!(f, "Non-temporary Addresses(IA_NA)")
            }
            Self::TemporaryAddresses => write!(f, "Temporary Addresses(IA_TA)"),
            Self::PrefixDelegation(d) => {
                write!(f, "Prefix Delegation(IA_PD)-{d}")
            } // Self::Stateless => "Stateless",
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
    pub request_opts: Vec<DhcpV6OptionCode>,
}

impl Default for DhcpV6Config {
    fn default() -> Self {
        Self {
            iface_name: String::new(),
            iface_index: 0,
            duid: DhcpV6Duid::Raw(Vec::new()),
            mode: DhcpV6Mode::default(),
            src_ip: Ipv6Addr::UNSPECIFIED,
            src_mac: None,
            timeout_sec: 0,
            request_opts: vec![
                DhcpV6OptionCode::OptionRequestOption,
                DhcpV6OptionCode::Preference,
                DhcpV6OptionCode::DnsServers,
                DhcpV6OptionCode::DomainList,
                DhcpV6OptionCode::NtpServer,
            ],
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

    /// Use MAC address of interface to setup DUID to
    /// `DhcpV6Duid::LinkLayerAddress`.
    pub async fn set_duid_by_iface_mac(
        &mut self,
    ) -> Result<&mut Self, DhcpError> {
        self.duid = if let Some(mac) = self.src_mac.as_ref() {
            DhcpV6Duid::LinkLayerAddress(DhcpV6DuidLinkLayerAddr::new(
                ARP_HW_TYPE_ETHERNET,
                mac,
            ))
        } else if let Ok((_, src_mac)) =
            get_iface_index_mac(&self.iface_name).await
        {
            DhcpV6Duid::LinkLayerAddress(DhcpV6DuidLinkLayerAddr::new(
                ARP_HW_TYPE_ETHERNET,
                &src_mac,
            ))
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

    /// Get DUID or initialize to DhcpV6Duid::LinkLayerAddress() when found MAC
    /// address of specified interface, fallback to `DhcpV6Duid::default()`
    /// if no MAC address.
    pub fn get_duid_or_init(&mut self) -> &DhcpV6Duid {
        if self.duid.is_empty() {
            self.duid = if let Some(mac) = self.src_mac.as_ref() {
                DhcpV6Duid::LinkLayerAddress(DhcpV6DuidLinkLayerAddr::new(
                    ARP_HW_TYPE_ETHERNET,
                    mac,
                ))
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

    pub fn request_extra_dhcp_opts(&mut self, opts: &[u16]) -> &mut Self {
        for opt in opts {
            self.request_opts.push((*opt).into());
        }
        self.request_opts.sort_unstable();
        self.request_opts.dedup();
        self
    }

    /// Specify arbitrary DHCP options to request.
    pub fn override_request_dhcp_opts(&mut self, opts: &[u16]) -> &mut Self {
        self.request_opts =
            opts.iter().map(|c| DhcpV6OptionCode::from(*c)).collect();
        self.request_opts.sort_unstable();
        self.request_opts.dedup();
        self
    }
}
