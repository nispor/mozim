use std::ffi::CString;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::unix::io::AsRawFd;

use nix::errno::Errno;

use crate::{
    bpf::apply_dhcp_bpf, mac::mac_address_to_eth_mac_bytes, DhcpError,
    DhcpV4Config, ErrorKind,
};

const BROADCAST_MAC_ADDRESS: &str = "ff:ff:ff:ff:ff:ff";
const PACKET_HOST: u8 = 0; // a packet addressed to the local host

#[derive(Debug, PartialEq, Clone, Default)]
pub(crate) struct DhcpRawSocket {
    config: DhcpV4Config,
    raw_fd: libc::c_int,
}

impl std::os::unix::io::AsRawFd for DhcpRawSocket {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.raw_fd as std::os::unix::io::RawFd
    }
}

impl Drop for DhcpRawSocket {
    fn drop(&mut self) {
        if self.raw_fd >= 0 {
            unsafe {
                libc::close(self.raw_fd);
            }
        }
    }
}

impl DhcpRawSocket {
    pub(crate) fn send_recv(
        &self,
        eth_pkg: &[u8],
    ) -> Result<Vec<u8>, DhcpError> {
        if self.raw_fd < 0 {
            let e = DhcpError::new(
                ErrorKind::Bug,
                "Please run DhcpSocket::open_raw() first".to_string(),
            );
            log::error!("{}", e);
            return Err(e);
        }
        self.send_raw(BROADCAST_MAC_ADDRESS, eth_pkg)?;
        self.recv_raw()
    }

    fn send_raw(
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
            log::debug!("Raw socket sent: {} bytes", sent_bytes);
            if sent_bytes <= 0 {
                let e = DhcpError::new(
                    ErrorKind::Bug,
                    format!(
                        "Failed to send data to socket {}: {}, data: {:?}",
                        self.raw_fd,
                        Errno::last(),
                        eth_pkg,
                    ),
                );
                log::error!("{}", e);
                return Err(e);
            }
        }
        Ok(())
    }

    fn recv_raw(&self) -> Result<Vec<u8>, DhcpError> {
        let mut src_addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        // TODO: Add support of `Maximum DHCP Message Size` option
        let mut buffer = [0u8; 1500];
        let mut addr_buffer_size: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        let addr_ptr = unsafe {
            std::mem::transmute::<*mut libc::sockaddr_ll, *mut libc::sockaddr>(
                &mut src_addr,
            )
        };

        unsafe {
            log::debug!("Raw socket receiving");
            let rc = libc::recvfrom(
                self.raw_fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0, // flags
                addr_ptr as *mut libc::sockaddr,
                &mut addr_buffer_size,
            );
            if rc <= 0 {
                let errno = Errno::last();
                let e = if errno == Errno::EAGAIN {
                    DhcpError::new(
                        ErrorKind::Timeout,
                        "Timeout on receiving data from socket".to_string(),
                    )
                } else {
                    DhcpError::new(
                        ErrorKind::Bug,
                        format!(
                            "Failed to recv from socket {}: {}",
                            self.raw_fd, errno
                        ),
                    )
                };
                log::error!("{}", e);
                return Err(e);
            }
            log::debug!("Raw socket received {:?}", &buffer[..rc as usize]);
        }
        Ok(buffer.to_vec())
    }

    pub(crate) fn new(config: &DhcpV4Config) -> Result<Self, DhcpError> {
        let iface_index = config.iface_index as libc::c_int;
        let eth_protocol = libc::ETH_P_ALL;
        let raw_fd = create_raw_socket(eth_protocol)?;
        bind_raw_socket(raw_fd, eth_protocol, iface_index, &config.iface_mac)?;
        set_socket_timeout(raw_fd, config.socket_timeout)?;

        apply_dhcp_bpf(raw_fd)?;
        log::debug!("Raw socket created {}", raw_fd);
        Ok(DhcpRawSocket {
            raw_fd,
            config: config.clone(),
        })
    }
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

#[derive(Debug, PartialEq, Clone, Default)]
pub(crate) struct DhcpUdpSocket {}

impl DhcpUdpSocket {
    pub(crate) fn send_recv(
        iface_name: &str,
        src_ip: &Ipv4Addr,
        dst_ip: &Ipv4Addr,
        pkg: &[u8],
        timeout: u32,
    ) -> Result<Vec<u8>, DhcpError> {
        let udp_socket = UdpSocket::bind(&format!(
            "{}:{}",
            src_ip,
            0 // Use random source port
        ))?;
        log::debug!("UDP socket bind to {:?}", udp_socket);
        let iface_name_cstr = CString::new(iface_name)?;

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
                        iface_name,
                        Errno::last(),
                    ),
                );
                log::error!("{}", e);
                return Err(e);
            }
        }
        udp_socket.set_read_timeout(Some(std::time::Duration::from_secs(
            timeout.into(),
        )))?;
        udp_socket.set_write_timeout(Some(std::time::Duration::from_secs(
            timeout.into(),
        )))?;
        udp_socket.connect(&format!(
            "{}:{}",
            dst_ip,
            dhcproto::v4::SERVER_PORT
        ))?;
        udp_socket.send(pkg)?;
        // TODO: Add support of `Maximum DHCP Message Size` option
        let mut buffer = [0u8; 1500];
        udp_socket.recv(&mut buffer)?;
        Ok(buffer.to_vec())
    }
}

fn set_socket_timeout(fd: libc::c_int, timeout: u32) -> Result<(), DhcpError> {
    let tmo = libc::timeval {
        tv_sec: timeout.into(),
        tv_usec: 0,
    };
    unsafe {
        let rc = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            (&tmo as *const libc::timeval) as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        if rc < 0 {
            return Err(DhcpError::new(
                ErrorKind::Bug,
                format!(
                    "Failed to set the send timeout SO_SNDTIMEO to \
                    socket {}: {}",
                    fd, rc
                ),
            ));
        }
        let rc = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tmo as *const libc::timeval) as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        if rc < 0 {
            let e = DhcpError::new(
                ErrorKind::Bug,
                format!(
                    "Failed to set the recv timeout SO_RCVTIMEO to \
                    socket {}: {}",
                    fd, rc
                ),
            );
            log::error!("{}", e);
            return Err(e);
        }
    }
    Ok(())
}
