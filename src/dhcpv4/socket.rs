// SPDX-License-Identifier: Apache-2.0

use std::{
    ffi::CString,
    future::Future,
    net::Ipv4Addr,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::io::RawFd,
    },
};

use nix::{
    errno::Errno,
    sys::socket::{AddressFamily, MsgFlags, SockFlag, SockProtocol, SockType},
};
use tokio::{io::unix::AsyncFd, net::UdpSocket};

use super::{
    bpf::apply_dhcp_bpf,
    msg::{DhcpV4Message, DhcpV4MessageType},
    proiscuous::enable_promiscuous_mode,
};
use crate::{DhcpError, DhcpV4Config, DhcpV4Lease, ErrorKind, ETH_ALEN};

const PACKET_HOST: u8 = 0; // a packet addressed to the local host
pub(crate) const SERVER_PORT: u16 = 67;
pub(crate) const CLIENT_PORT: u16 = 68;

pub(crate) trait DhcpV4Socket {
    fn recv(&self) -> impl Future<Output = Result<Vec<u8>, DhcpError>> + Send;
    fn send(
        &self,
        buffer: &[u8],
    ) -> impl Future<Output = Result<(), DhcpError>> + Send;

    fn is_raw(&self) -> bool;

    fn recv_dhcp_lease(
        &self,
        expected: DhcpV4MessageType,
        xid: u32,
    ) -> impl Future<Output = Result<Option<DhcpV4Lease>, DhcpError>> + Send
    where
        Self: Sync,
    {
        async move {
            let buffer: Vec<u8> = self.recv().await?;
            log::trace!("Received DHCP reply {buffer:?}");
            let reply_dhcp_msg = if self.is_raw() {
                DhcpV4Message::parse_eth_packet(&buffer)?
            } else {
                DhcpV4Message::parse(&buffer)?
            };
            let message_type = if let Some(t) = reply_dhcp_msg.message_type() {
                t
            } else {
                log::debug!(
                    "Dropping DHCP message due to missing message type option"
                );
                return Ok(None);
            };
            if reply_dhcp_msg.xid != xid {
                log::debug!(
                    "Dropping DHCP message due to xid miss-match. Expecting \
                     {}, got {}",
                    xid,
                    reply_dhcp_msg.xid
                );
                return Ok(None);
            }
            if message_type != expected {
                log::debug!(
                    "Dropping DHCP message due to type miss-match. Expecting \
                     {expected}, got {message_type}",
                );
                return Ok(None);
            }
            if let Some(lease) = reply_dhcp_msg.lease() {
                Ok(Some(lease))
            } else {
                log::debug!(
                    "No lease found in the reply from DHCP server \
                     {reply_dhcp_msg:?}"
                );
                Ok(None)
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct DhcpRawSocket {
    fd: AsyncFd<OwnedFd>,
}

impl DhcpRawSocket {
    pub(crate) fn new(config: &DhcpV4Config) -> Result<Self, DhcpError> {
        let iface_index = config.iface_index as libc::c_int;
        let fd = create_raw_eth_socket()?;

        apply_dhcp_bpf(fd.as_raw_fd())?;

        bind_raw_socket(
            fd.as_raw_fd(),
            libc::ETH_P_ALL,
            iface_index,
            &config.src_mac,
        )?;

        if config.is_proxy {
            enable_promiscuous_mode(fd.as_raw_fd(), iface_index)?;
        }

        log::debug!("Raw socket created {}", fd.as_raw_fd());
        Ok(DhcpRawSocket {
            fd: AsyncFd::new(fd)?,
        })
    }
}

impl DhcpV4Socket for DhcpRawSocket {
    fn is_raw(&self) -> bool {
        true
    }

    async fn send(&self, eth_packet: &[u8]) -> Result<(), DhcpError> {
        let mut sent = 0;
        log::trace!("Sending ethernet packet: {eth_packet:?}");
        while sent < eth_packet.len() {
            let mut guard = self.fd.writable().await?;

            let _ = guard
                .try_io(|inner| {
                    sent += nix::sys::socket::send(
                        inner.get_ref().as_raw_fd(),
                        &eth_packet[sent..],
                        MsgFlags::empty(),
                    )?;
                    Ok(())
                })
                .map_err(|e| {
                    DhcpError::new(
                        ErrorKind::IoError,
                        format!("Failed to send packet to raw socket: {e:?}"),
                    )
                })?;
        }

        Ok(())
    }

    // TODO:
    //  * Receive till `Maximum DHCP Message Size`
    async fn recv(&self) -> Result<Vec<u8>, DhcpError> {
        let mut buffer = [0u8; 1500];
        let rc = loop {
            let mut guard = self.fd.readable().await?;

            if let Ok(s) = guard.try_io(|inner| {
                Ok(nix::sys::socket::recv(
                    inner.get_ref().as_raw_fd(),
                    &mut buffer,
                    MsgFlags::empty(),
                )?)
            }) {
                break s?;
            }
        };

        log::trace!("Raw socket received {:?}", &buffer[..rc]);
        Ok(buffer[..rc].to_vec())
    }
}

fn create_raw_eth_socket() -> Result<OwnedFd, DhcpError> {
    nix::sys::socket::socket(
        AddressFamily::Packet,
        SockType::Raw,
        SockFlag::SOCK_NONBLOCK,
        Some(SockProtocol::EthAll),
    )
    .map_err(|e| {
        DhcpError::new(
            ErrorKind::Bug,
            format!("Failed to create raw ethernet socket: {e}"),
        )
    })
}

fn bind_raw_socket(
    fd: RawFd,
    eth_protocol: libc::c_int,
    iface_index: libc::c_int,
    mac_address: &[u8; ETH_ALEN],
) -> Result<(), DhcpError> {
    let mut sll_addr: [libc::c_uchar; 8] = [0; 8];

    sll_addr[..ETH_ALEN].clone_from_slice(&mac_address[..ETH_ALEN]);

    let mut socket_addr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as libc::c_ushort,
        sll_protocol: (eth_protocol as libc::c_ushort).to_be(),
        sll_ifindex: iface_index,
        sll_hatype: libc::ARPHRD_ETHER as libc::c_ushort,
        sll_pkttype: PACKET_HOST as libc::c_uchar,
        sll_halen: libc::ETH_ALEN as libc::c_uchar,
        sll_addr,
    };

    unsafe {
        let addr_ptr = std::mem::transmute::<
            *mut libc::sockaddr_ll,
            *mut libc::sockaddr,
        >(&mut socket_addr);
        match libc::bind(
            fd,
            addr_ptr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        ) {
            0 => Ok(()),
            rc => {
                libc::close(fd);
                Err(DhcpError::new(
                    ErrorKind::Bug,
                    format!("Failed to bind socket: {rc}"),
                ))
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct DhcpUdpV4Socket {
    socket: UdpSocket,
}

impl DhcpUdpV4Socket {
    pub(crate) async fn new(
        iface_name: &str,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
    ) -> Result<Self, DhcpError> {
        log::debug!(
            "Creating UDP socket from {src_ip}:{} to {dst_ip}:{}",
            CLIENT_PORT,
            SERVER_PORT
        );
        let socket = UdpSocket::bind((src_ip, CLIENT_PORT)).await?;
        bind_socket_to_iface(socket.as_raw_fd(), iface_name)?;
        socket.connect((dst_ip, SERVER_PORT)).await?;
        log::debug!("Finished UDP socket creation");

        Ok(Self { socket })
    }
}

impl DhcpV4Socket for DhcpUdpV4Socket {
    fn is_raw(&self) -> bool {
        false
    }

    async fn send(&self, packet: &[u8]) -> Result<(), DhcpError> {
        log::trace!("Sending DHCP packet: {packet:?}");
        let mut sent = 0;
        while sent < packet.len() {
            sent += self.socket.send(&packet[sent..]).await?;
        }
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>, DhcpError> {
        // TODO: Add support of `Maximum DHCP Message Size` option
        let mut buffer = [0u8; 1500];
        let received = self.socket.recv(&mut buffer).await?;
        Ok(buffer[..received].to_vec())
    }
}

fn bind_socket_to_iface(fd: RawFd, iface_name: &str) -> Result<(), DhcpError> {
    let iface_name_cstr = CString::new(iface_name)?;

    unsafe {
        let rc = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface_name_cstr.as_ptr() as *const libc::c_void,
            std::mem::size_of::<CString>() as libc::socklen_t,
        );
        if rc != 0 {
            return Err(DhcpError::new(
                ErrorKind::Bug,
                format!(
                    "Failed to bind socket to interface {} with error: {}",
                    iface_name,
                    Errno::last(),
                ),
            ));
        }
    }
    Ok(())
}
