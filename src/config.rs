use crate::{mac::mac_str_to_u8_array, DhcpError, ErrorKind};

// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2
const ARP_HW_TYPE_ETHERNET: u8 = 1;

const DEFAULT_TIMEOUT: u32 = 120;
const DEFAULT_SOCKET_TIMEOUT: u32 = 5;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DhcpV4Config {
    pub(crate) iface_name: String,
    pub(crate) iface_index: u32,
    pub(crate) iface_mac: String,
    pub(crate) client_id: Vec<u8>,
    pub(crate) host_name: String,
    // TODO: Support allow list and deny list for DHCP servers.
    pub(crate) use_host_name_as_client_id: bool,
    pub(crate) timeout: u32,
    pub(crate) socket_timeout: u32,
}

impl Default for DhcpV4Config {
    fn default() -> Self {
        Self {
            iface_name: String::new(),
            iface_index: 0,
            iface_mac: String::new(),
            client_id: Vec::new(),
            host_name: String::new(),
            use_host_name_as_client_id: false,
            timeout: DEFAULT_TIMEOUT,
            socket_timeout: DEFAULT_SOCKET_TIMEOUT,
        }
    }
}

impl DhcpV4Config {
    pub fn new(iface_name: &str) -> Result<Self, DhcpError> {
        let np_iface = get_nispor_iface(iface_name)?;
        Ok(Self {
            iface_name: np_iface.name.to_string(),
            iface_index: np_iface.index,
            iface_mac: np_iface.mac_address,
            ..Default::default()
        })
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
        self.use_host_name_as_client_id = false;
        self.client_id
            .append(&mut mac_str_to_u8_array(&self.iface_mac));
        self
    }

    pub fn use_host_name_as_client_id(&mut self) -> &mut Self {
        // RFC 2132: 9.14. Client-identifier
        // Type 0 is used when not using hardware address
        self.client_id = vec![0];
        // The RFC never mentioned the NULL terminator for string.
        // TODO: Need to check with dnsmasq implementation
        self.client_id.extend_from_slice(self.host_name.as_bytes());
        self.use_host_name_as_client_id = true;
        self
    }
}

// TODO: Using NetState::retrieve() has performance issue here when there are
// a lot route entries.
fn get_nispor_iface(iface_name: &str) -> Result<nispor::Iface, DhcpError> {
    if iface_name.is_empty() {
        let e = DhcpError::new(
            ErrorKind::InvalidArgument,
            "Interface name not defined".to_string(),
        );
        log::error!("{}", e);
        return Err(e);
    }
    let net_state = match nispor::NetState::retrieve() {
        Ok(s) => s,
        Err(e) => {
            return Err(DhcpError::new(
                ErrorKind::Bug,
                format!("Faild to retrieve network state: {}", e),
            ))
        }
    };
    if let Some(iface) = net_state.ifaces.get(iface_name) {
        Ok(iface.clone())
    } else {
        Err(DhcpError::new(
            ErrorKind::InvalidArgument,
            format!("Interface {} not found", iface_name),
        ))
    }
}
