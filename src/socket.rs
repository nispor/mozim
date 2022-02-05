use std::ffi::CString;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::unix::io::AsRawFd;

use crate::{
    bpf::apply_dhcp_bpf, mac::mac_address_to_eth_mac_bytes, DhcpError,
    DhcpV4Config, DhcpV4Message, ErrorKind,
};

const PACKET_HOST: u8 = 0; // a packet addressed to the local host

#[derive(Debug, PartialEq, Clone, Default)]
pub(crate) struct DhcpSocket {
    raw_fd: libc::c_int,
    config: DhcpV4Config,
}

impl std::os::unix::io::AsRawFd for DhcpSocket {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.raw_fd as std::os::unix::io::RawFd
    }
}

impl Drop for DhcpSocket {
    fn drop(&mut self) {
        if self.raw_fd >= 0 {
            unsafe {
                libc::close(self.raw_fd);
            }
        }
    }
}

impl DhcpSocket {
    pub(crate) fn send_unicast(
        &self,
        src_ip: &Ipv4Addr,
        dst_ip: &Ipv4Addr,
        pkg: &[u8],
    ) -> Result<(), DhcpError> {
        println!("src ip {:?}", src_ip);
        let udp_socket = UdpSocket::bind(&format!(
            "{}:{}",
            src_ip,
            0 // Use random source port
        ))?;
        log::debug!("UDP socket bind to {:?}", udp_socket);
        let iface_name_cstr = CString::new(self.config.iface_name.as_str())?;

        unsafe {
            let rc = libc::setsockopt(
                udp_socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                iface_name_cstr.as_ptr() as *const libc::c_void,
                std::mem::size_of::<CString>() as libc::socklen_t,
            );
            if rc != 0 {
                let e = DhcpError::new(
                    ErrorKind::Bug,
                    format!(
                        "Failed to bind socket to interface {} with error: {}",
                        self.config.iface_name, rc
                    ),
                );
                log::error!("{}", e);
                return Err(e);
            }
        }
        udp_socket.connect(&format!(
            "{}:{}",
            dst_ip,
            dhcproto::v4::SERVER_PORT
        ))?;
        udp_socket.send(pkg)?;
        Ok(())
    }

    pub(crate) fn send_raw(
        &self,
        dst_mac_addr: &str,
        eth_pkg: &[u8],
    ) -> Result<(), DhcpError> {
        let mut dst_addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        dst_addr.sll_halen = libc::ETH_ALEN as u8;

        dst_addr.sll_addr[..libc::ETH_ALEN as usize]
            .clone_from_slice(&mac_address_to_eth_mac_bytes(dst_mac_addr)?);
        dst_addr.sll_ifindex = self.config.iface_index as i32;
        let addr_buffer_size: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        let addr_ptr = unsafe {
            std::mem::transmute::<*mut libc::sockaddr_ll, *mut libc::sockaddr>(
                &mut dst_addr,
            )
        };

        unsafe {
            log::debug!("Sending raw ethernet package: {:?}", eth_pkg);
            let sent_bytes = libc::sendto(
                self.raw_fd,
                eth_pkg.as_ptr() as *mut libc::c_void,
                eth_pkg.len(),
                0, // flags
                addr_ptr as *mut libc::sockaddr,
                addr_buffer_size,
            );
            log::debug!("sent: {} bytes", sent_bytes);
            if sent_bytes <= 0 {
                log::debug!("errno: {}", nix::errno::errno());
            }
        }

        Ok(())
    }

    pub fn recv_dhcpv4_reply(&self) -> Result<DhcpV4Message, DhcpError> {
        let mut src_addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        // TODO: Use iface MTU
        let mut buffer = [0u8; 1500];
        let mut addr_buffer_size: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        let addr_ptr = unsafe {
            std::mem::transmute::<*mut libc::sockaddr_ll, *mut libc::sockaddr>(
                &mut src_addr,
            )
        };

        unsafe {
            log::debug!("receiving");
            log::debug!(
                "recv: {} bytes",
                libc::recvfrom(
                    self.raw_fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0, // flags
                    addr_ptr as *mut libc::sockaddr,
                    &mut addr_buffer_size
                )
            );
        }
        log::debug!("received {:?}", buffer);

        DhcpV4Message::try_from(buffer.as_slice())
    }

    pub fn new(config: &DhcpV4Config) -> Result<Self, DhcpError> {
        let iface_index = config.iface_index as libc::c_int;
        let eth_protocol = libc::ETH_P_ALL;
        let raw_fd = create_raw_socket(eth_protocol)?;
        log::debug!("socket raw_fd is {}", raw_fd);

        bind_raw_socket(raw_fd, eth_protocol, iface_index, &config.iface_mac)?;

        accept_all_mac_address(raw_fd, iface_index)?;

        apply_dhcp_bpf(raw_fd)?;

        Ok(DhcpSocket {
            raw_fd,
            config: config.clone(),
        })
    }
}

fn accept_all_mac_address(
    fd: libc::c_int,
    iface_index: libc::c_int,
) -> Result<(), DhcpError> {
    let mreq = libc::packet_mreq {
        mr_ifindex: iface_index,
        mr_type: libc::PACKET_MR_PROMISC as libc::c_ushort,
        mr_alen: 0,
        mr_address: [0; 8],
    };

    unsafe {
        let rc = libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_ADD_MEMBERSHIP,
            (&mreq as *const libc::packet_mreq) as *const libc::c_void,
            std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
        );
        if rc != 0 {
            return Err(DhcpError::new(
                ErrorKind::Bug,
                format!(
                    "Failed to set socket to promiscuous mode with error: {}",
                    rc
                ),
            ));
        }
    }
    Ok(())
}

fn create_raw_socket(
    eth_protocol: libc::c_int,
) -> Result<libc::c_int, DhcpError> {
    unsafe {
        match libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            eth_protocol.to_be() as libc::c_int,
        ) {
            -1 => Err(DhcpError::new(
                ErrorKind::Bug,
                "libc::socket() failed with -1".to_string(),
            )),
            fd => Ok(fd),
        }
    }
}

fn bind_raw_socket(
    fd: libc::c_int,
    eth_protocol: libc::c_int,
    iface_index: libc::c_int,
    mac_address: &str,
) -> Result<(), DhcpError> {
    let mut sll_addr: [libc::c_uchar; 8] = [0; 8];

    sll_addr[..libc::ETH_ALEN as usize]
        .clone_from_slice(&mac_address_to_eth_mac_bytes(mac_address)?);

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
                    format!("Failed to bind socket: {}", rc),
                ))
            }
        }
    }
}

/*
fn gen_send_fd(
    src_ip: &str,
    src_port: u16,
    iface_name: &str,
) -> Result<UdpSocket, DhcpError> {
    let socket = UdpSocket::bind(&format!("{}:{}", src_ip, src_port))?;
    let iface_name_cstr = CString::new(iface_name)?;

    unsafe {
        let rc = libc::setsockopt(
            socket.as_raw_fd(),
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
                    iface_name, rc
                ),
            ));
        }
    }
    Ok(socket)
}
*/
