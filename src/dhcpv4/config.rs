// SPDX-License-Identifier: Apache-2.0

use dhcproto::v4::OptionCode;

use super::option::V4_OPT_CODE_MS_CLASSLESS_STATIC_ROUTE;
use crate::{
    mac::mac_str_to_u8_array, nispor::get_nispor_iface,
    socket::DEFAULT_SOCKET_TIMEOUT, DhcpError,
};

// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2
const ARP_HW_TYPE_ETHERNET: u8 = 1;

const DEFAULT_TIMEOUT: u32 = 120;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DhcpV4Config {
    pub(crate) iface_name: String,
    pub(crate) iface_index: u32,
    pub(crate) src_mac: String,
    pub(crate) client_id: Vec<u8>,
    pub(crate) host_name: String,
    // TODO: Support allow list and deny list for DHCP servers.
    pub(crate) timeout: u32,
    pub(crate) socket_timeout: u32,
    pub(crate) is_proxy: bool,
    pub(crate) request_opts: Vec<OptionCode>,
}

impl Default for DhcpV4Config {
    fn default() -> Self {
        Self {
            iface_name: String::new(),
            iface_index: 0,
            src_mac: String::new(),
            client_id: Vec::new(),
            host_name: String::new(),
            timeout: DEFAULT_TIMEOUT,
            socket_timeout: DEFAULT_SOCKET_TIMEOUT,
            is_proxy: false,
            request_opts: vec![
                OptionCode::Hostname,
                OptionCode::SubnetMask,
                OptionCode::Router,
                OptionCode::DomainNameServer,
                OptionCode::DomainName,
                OptionCode::InterfaceMtu,
                OptionCode::NtpServers,
                OptionCode::ClasslessStaticRoute,
                OptionCode::Unknown(V4_OPT_CODE_MS_CLASSLESS_STATIC_ROUTE),
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

    // Check whether interface exists and resolve iface_index and MAC
    pub(crate) fn init(&mut self) -> Result<(), DhcpError> {
        let np_iface = get_nispor_iface(self.iface_name.as_str(), false)?;
        self.iface_index = np_iface.index;
        if !self.is_proxy {
            self.src_mac = np_iface.mac_address;
        }
        Ok(())
    }

    pub fn new_proxy(out_iface_name: &str, proxy_mac: &str) -> Self {
        Self {
            iface_name: out_iface_name.to_string(),
            src_mac: proxy_mac.to_string(),
            is_proxy: true,
            ..Default::default()
        }
    }

    // Set timeout in seconds
    pub fn set_timeout(&mut self, timeout: u32) -> &mut Self {
        self.timeout = timeout;
        self
    }

    pub fn set_host_name(&mut self, host_name: &str) -> &mut Self {
        self.host_name = host_name.to_string();
        self
    }

    pub fn use_mac_as_client_id(&mut self) -> &mut Self {
        self.client_id = vec![ARP_HW_TYPE_ETHERNET];
        self.client_id
            .append(&mut mac_str_to_u8_array(&self.src_mac));
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
        self.request_opts = opts.iter().map(|c| OptionCode::from(*c)).collect();
        self.request_opts.sort_unstable();
        self.request_opts.dedup();
        self
    }
}
