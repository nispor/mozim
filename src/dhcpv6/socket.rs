// SPDX-License-Identifier: Apache-2.0

use std::net::{Ipv6Addr, SocketAddrV6};

use tokio::net::UdpSocket;

use super::msg::{DhcpV6Message, DhcpV6MessageType};
use crate::{DhcpError, DhcpV6Lease};

/// RFC 8415: All_DHCP_Relay_Agents_and_Servers
const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

const CLIENT_PORT: u16 = 546;
const SERVER_PORT: u16 = 547;

#[derive(Debug)]
pub(crate) struct DhcpUdpV6Socket {
    socket: UdpSocket,
}

impl DhcpUdpV6Socket {
    pub(crate) async fn new(
        iface_name: &str,
        iface_index: u32,
        src_ip: Ipv6Addr,
    ) -> Result<Self, DhcpError> {
        let so_addr = SocketAddrV6::new(src_ip, CLIENT_PORT, 0, iface_index);
        log::debug!(
            "Creating UDP socket on [{src_ip}]:{} on interface \
             {iface_name}(index {iface_index})",
            CLIENT_PORT,
        );
        let socket = UdpSocket::bind(so_addr).await?;

        log::debug!("Finished UDP socket creation");
        Ok(Self { socket })
    }

    /*
    pub(crate) async fn send_unicast(
        &mut self,
        dst_ip: Ipv6Addr,
        packet: &[u8],
    ) -> Result<(), DhcpError> {
        log::trace!("Sending DHCPv6 packet unicast to {dst_ip}");
        let mut sent = 0;
        while sent < packet.len() {
            sent += self
                .socket
                .send_to(&packet[sent..], (dst_ip, SERVER_PORT))
                .await?;
        }
        Ok(())
    }
    */

    pub(crate) async fn send_multicast(
        &mut self,
        packet: &[u8],
    ) -> Result<(), DhcpError> {
        let dst_ip = ALL_DHCP_RELAY_AGENTS_AND_SERVERS;
        log::trace!(
            "Sending DHCPv6 packet multicast to all DHCPv6 servers and replays"
        );
        let mut sent = 0;
        while sent < packet.len() {
            sent += self
                .socket
                .send_to(&packet[sent..], (dst_ip, SERVER_PORT))
                .await?;
        }
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>, DhcpError> {
        let mut buffer = [0u8; 1500];
        // TODO(Gris Ge): Retry till end of packet or DHCPv6 max length
        let received = self.socket.recv(&mut buffer).await?;
        log::trace!("Received packet: {received:?}");
        Ok(buffer[..received].to_vec())
    }

    pub(crate) async fn recv_dhcp_lease(
        &self,
        expected: DhcpV6MessageType,
        xid: u32,
    ) -> Result<Option<DhcpV6Lease>, DhcpError> {
        let buffer: Vec<u8> = self.recv().await?;
        let reply_dhcp_msg = DhcpV6Message::parse(&buffer)?;
        log::trace!("Received DHCPv6 message {reply_dhcp_msg:?}");
        if reply_dhcp_msg.xid() != xid {
            log::debug!(
                "Dropping DHCPv6 message due to xid miss-match. Expecting {}, \
                 got {}",
                xid,
                reply_dhcp_msg.xid()
            );
            return Ok(None);
        }
        if reply_dhcp_msg.msg_type != expected {
            log::debug!(
                "Dropping DHCPv6 message due to type miss-match. Expecting \
                 {}, got {}",
                expected,
                reply_dhcp_msg.msg_type
            );
            return Ok(None);
        }
        match DhcpV6Lease::new_from_msg(&reply_dhcp_msg) {
            Ok(lease) => Ok(Some(lease)),
            Err(e) => {
                log::debug!(
                    "No lease found in the reply from DHCPv6 server {e}"
                );
                Ok(None)
            }
        }
    }
}
