use crate::{
    socket::DhcpSocket, DhcpError, DhcpV4Config, DhcpV4Lease, DhcpV4Message,
    DhcpV4MessageType, ErrorKind,
};

const BROADCAST_MAC_ADDRESS: &str = "ff:ff:ff:ff:ff:ff";

#[derive(Debug, PartialEq, Clone, Default)]
pub struct DhcpV4Client {
    config: DhcpV4Config,
    socket: DhcpSocket,
}

impl DhcpV4Client {
    pub fn new(config: DhcpV4Config) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    pub fn request(
        &self,
        lease: Option<DhcpV4Lease>,
    ) -> Result<DhcpV4Lease, DhcpError> {
        let mut dhcp_msg =
            DhcpV4Message::new(&self.config, DhcpV4MessageType::Discovery);
        if let Some(lease) = lease {
            dhcp_msg.load_lease(lease);
        }

        let socket = DhcpSocket::new(&self.config)?;

        socket.send(
            self.config.iface_index as i32,
            BROADCAST_MAC_ADDRESS,
            &dhcp_msg.to_eth_pkg()?,
        )?;
        let reply_dhcp_msg = socket.recv_dhcpv4_reply()?;
        reply_dhcp_msg.lease.ok_or_else(|| {
            let e = DhcpError::new(
                ErrorKind::NoLease,
                "DHCP server did not provide any DHCPv4 lease".to_string(),
            );
            log::error!("{}", e);
            e
        })
    }

    pub fn run(&self, lease: &DhcpV4Lease) -> Result<DhcpV4Lease, DhcpError> {
        todo!()
    }
}
