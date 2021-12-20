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
        let socket = DhcpSocket::new(&self.config)?;
        let ack_dhcp_msg = if let Some(lease) = lease {
            self.dhcp_request(&socket, lease)?
        } else {
            let offer_msg = self.dhcp_discovery(&socket)?;
            self.dhcp_request(
                &socket,
                offer_msg.lease.ok_or_else(|| {
                    let e = DhcpError::new(
                        ErrorKind::InvalidDhcpServerReply,
                        "No lease reply from DHCP server".to_string(),
                    );
                    log::debug!("{}", e);
                    e
                })?,
            )?
        };
        ack_dhcp_msg.lease.ok_or_else(|| {
            let e = DhcpError::new(
                ErrorKind::NoLease,
                "DHCP server provide no lease reply".to_string(),
            );
            log::debug!("{}", e);
            e
        })
    }

    fn dhcp_discovery(
        &self,
        socket: &DhcpSocket,
    ) -> Result<DhcpV4Message, DhcpError> {
        let dhcp_msg =
            DhcpV4Message::new(&self.config, DhcpV4MessageType::Discovery);

        socket.send(
            self.config.iface_index as i32,
            BROADCAST_MAC_ADDRESS,
            &dhcp_msg.to_eth_pkg()?,
        )?;
        let reply_dhcp_msg = socket.recv_dhcpv4_reply()?;
        if reply_dhcp_msg.msg_type != DhcpV4MessageType::Offer {
            let e = DhcpError::new(
                ErrorKind::InvalidDhcpServerReply,
                format!(
                    "Invalid message type reply from DHCP server, \
                    expecting DHCP offer, got {}: debug {:?}",
                    reply_dhcp_msg.msg_type, reply_dhcp_msg
                ),
            );
            log::debug!("{}", e);
            return Err(e);
        }
        Ok(reply_dhcp_msg)
    }

    fn dhcp_request(
        &self,
        socket: &DhcpSocket,
        lease: DhcpV4Lease,
    ) -> Result<DhcpV4Message, DhcpError> {
        let mut dhcp_msg =
            DhcpV4Message::new(&self.config, DhcpV4MessageType::Request);
        dhcp_msg.load_lease(lease);
        socket.send(
            self.config.iface_index as i32,
            BROADCAST_MAC_ADDRESS,
            &dhcp_msg.to_eth_pkg()?,
        )?;
        let reply_dhcp_msg = socket.recv_dhcpv4_reply()?;
        if reply_dhcp_msg.msg_type != DhcpV4MessageType::Ack {
            let e = DhcpError::new(
                ErrorKind::InvalidDhcpServerReply,
                format!(
                    "Invalid message type reply from DHCP server, \
                    expecting DHCP ack, got {}: debug {:?}",
                    reply_dhcp_msg.msg_type, reply_dhcp_msg
                ),
            );
            log::debug!("{}", e);
            return Err(e);
        }
        Ok(reply_dhcp_msg)
    }

    pub fn run(&self, lease: &DhcpV4Lease) -> Result<DhcpV4Lease, DhcpError> {
        todo!()
    }
}
