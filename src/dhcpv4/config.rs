// SPDX-License-Identifier: Apache-2.0

use crate::{mac::parse_mac, DhcpError, DhcpV4OptionCode, ErrorKind, ETH_ALEN};

// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2
const ARP_HW_TYPE_ETHERNET: u8 = 1;

// TODO: Support allow list and deny list for DHCP servers.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DhcpV4Config {
    /// Interface to run DHCP against.
    pub iface_name: String,
    /// Interface index to run DHCP against.
    pub iface_index: u32,
    /// MAC address of interface or proxy.
    pub(crate) src_mac: [u8; ETH_ALEN],
    pub(crate) client_id: Vec<u8>,
    pub(crate) host_name: String,
    /// Whether acting as DHCP proxy(whether mozim should listen on DHCP reply
    /// not target for interface MAC address).
    pub is_proxy: bool,
    pub(crate) request_opts: Vec<DhcpV4OptionCode>,
    /// Timeout in seconds for getting/refreshing lease.
    /// 0 means infinitely.
    /// By default is wait infinitely.
    pub timeout_sec: u32,
}

impl Default for DhcpV4Config {
    fn default() -> Self {
        Self {
            iface_name: String::new(),
            iface_index: 0,
            src_mac: [0u8; ETH_ALEN],
            client_id: Vec::new(),
            host_name: String::new(),
            is_proxy: false,
            timeout_sec: 0,
            request_opts: vec![
                DhcpV4OptionCode::HostName,
                DhcpV4OptionCode::SubnetMask,
                DhcpV4OptionCode::Router,
                DhcpV4OptionCode::DomainNameServer,
                DhcpV4OptionCode::DomainName,
                DhcpV4OptionCode::InterfaceMtu,
                DhcpV4OptionCode::NtpServers,
                DhcpV4OptionCode::ClasslessStaticRoute,
                DhcpV4OptionCode::MS_CLASSLESS_STATIC_ROUTE,
            ],
        }
    }
}

impl DhcpV4Config {
    pub fn new(iface_name: &str) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            ..Default::default()
        }
    }

    pub fn set_iface_index(&mut self, index: u32) -> &mut Self {
        self.iface_index = index;
        self
    }

    pub fn set_iface_mac(&mut self, mac: &str) -> Result<&mut Self, DhcpError> {
        let src_mac = parse_mac(mac)?;
        self.set_iface_mac_raw(&src_mac)
    }

    pub fn set_iface_mac_raw(
        &mut self,
        mac: &[u8],
    ) -> Result<&mut Self, DhcpError> {
        if mac.len() != ETH_ALEN {
            return Err(DhcpError::new(
                ErrorKind::NotSupported,
                format!("Only support ethernet MAC address({ETH_ALEN} bytes)",),
            ));
        }
        self.src_mac.copy_from_slice(&mac[..ETH_ALEN]);
        Ok(self)
    }

    pub(crate) fn need_resolve(&self) -> bool {
        self.iface_index == 0 || self.src_mac.is_empty()
    }

    #[cfg(feature = "netlink")]
    pub(crate) async fn resolve(&mut self) -> Result<(), DhcpError> {
        if self.is_proxy {
            self.iface_index =
                crate::netlink::get_iface_index(&self.iface_name).await?;
        } else {
            let (iface_index, src_mac) =
                crate::netlink::get_iface_index_mac(&self.iface_name).await?;

            if src_mac.len() != ETH_ALEN {
                return Err(DhcpError::new(
                    ErrorKind::NotSupported,
                    format!(
                        "Interface {} is holding MAC address {:?} which is not
                    supported yet, only support MAC with {} u8",
                        self.iface_name, src_mac, ETH_ALEN,
                    ),
                ));
            } else {
                self.iface_index = iface_index;
                self.src_mac.copy_from_slice(&src_mac[..ETH_ALEN]);
            }
        }
        Ok(())
    }

    #[cfg(not(feature = "netlink"))]
    pub(crate) async fn resolve(&mut self) -> Result<(), DhcpError> {
        Err(DhcpError::new(
            ErrorKind::InvalidArgument,
            format!(
                "Feature `netlink` not enabled, cannot resolve interface {} \
                 index and mac address, please set them manually",
                self.iface_name,
            ),
        ))
    }

    pub fn new_proxy(
        out_iface_name: &str,
        proxy_mac: &str,
    ) -> Result<Self, DhcpError> {
        let mac = parse_mac(proxy_mac)?;
        if mac.len() != ETH_ALEN {
            Err(DhcpError::new(
                ErrorKind::NotSupported,
                format!(
                    "Supported MAC address {proxy_mac}, expecting format \
                     01:02:2a:2c:f7:04"
                ),
            ))
        } else {
            let mut src_mac = [0; ETH_ALEN];
            src_mac.copy_from_slice(&mac[..ETH_ALEN]);
            Ok(Self {
                iface_name: out_iface_name.to_string(),
                src_mac,
                is_proxy: true,
                ..Default::default()
            })
        }
    }

    pub fn set_host_name(&mut self, host_name: &str) -> &mut Self {
        self.host_name = host_name.to_string();
        self
    }

    pub fn use_mac_as_client_id(&mut self) -> &mut Self {
        self.client_id = vec![ARP_HW_TYPE_ETHERNET];
        self.client_id.extend_from_slice(&self.src_mac);
        self
    }

    pub fn use_host_name_as_client_id(&mut self) -> &mut Self {
        if !self.host_name.is_empty() {
            // RFC 2132: 9.14. Client-identifier
            // Type 0 is used when not using hardware address
            // The RFC never mentioned the NULL terminator for string.
            // TODO: Need to check with dnsmasq implementation
            let host_name = self.host_name.clone();
            self.set_client_id(0, host_name.as_bytes());
        }
        self
    }

    /// Timeout in seconds for getting/refreshing lease.
    /// 0 means infinitely.
    /// By default is wait infinitely.
    pub fn set_timeout_sec(&mut self, timeout_sec: u32) -> &mut Self {
        self.timeout_sec = timeout_sec;
        self
    }

    pub fn set_client_id(
        &mut self,
        client_id_type: u8,
        client_id: &[u8],
    ) -> &mut Self {
        // RFC 2132: 9.14. Client-identifier
        self.client_id = vec![client_id_type];
        self.client_id.extend_from_slice(client_id);
        self
    }

    /// By default, these DHCP options will be requested from DHCP server:
    /// * Hostname (12)
    /// * Subnet Mask (1)
    /// * Router (3)
    /// * Domain Name Server (6)
    /// * Domain Name (15)
    /// * Interface MTU (26)
    /// * NTP Servers (42)
    /// * Classless Static Route (121)
    /// * Microsoft Classless Static Route (249)
    ///
    /// This function will append specified DHCP option to above list.
    pub fn request_extra_dhcp_opts(&mut self, opts: &[u8]) -> &mut Self {
        for opt in opts {
            self.request_opts.push((*opt).into());
        }
        self.request_opts.sort_unstable();
        self.request_opts.dedup();
        self
    }

    /// Specify arbitrary DHCP options to request.
    pub fn override_request_dhcp_opts(&mut self, opts: &[u8]) -> &mut Self {
        self.request_opts =
            opts.iter().map(|c| DhcpV4OptionCode::from(*c)).collect();
        self.request_opts.sort_unstable();
        self.request_opts.dedup();
        self
    }
}
