use libc;
use nispor::{Iface, NetState};
use nix;

use crate::{
    bpf::apply_dhcp_bpf, Dhcp4Message, DhcpError, Emitable, ErrorKind,
};

const PACKET_HOST: u8 = 0; // a packet addressed to the local host

pub struct DhcpSocket {
    fd: libc::c_int,
    iface: Iface,
}

impl std::os::unix::io::AsRawFd for DhcpSocket {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.fd as std::os::unix::io::RawFd
    }
}

impl DhcpSocket {
    pub fn close(&self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    pub fn send_dhcp_request(&self, host_name: &str) -> Result<(), DhcpError> {
        let mut dhcp_msg = Dhcp4Message::new()
            .set_host_name(host_name)?
            .set_hw_addr(&self.iface.mac_address)?
            .request();
        let mut buffer = vec![0; dhcp_msg.buffer_len()];
        dhcp_msg.emit(&mut buffer);
        let mut sender_addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let addr_buffer_size: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        let addr_ptr = unsafe {
            std::mem::transmute::<*mut libc::sockaddr_ll, *mut libc::sockaddr>(
                &mut sender_addr,
            )
        };
        unsafe {
            println!("sending: {:?}", buffer);
            println!(
                "sent: {} bytes",
                libc::sendto(
                    self.fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0, // flags
                    addr_ptr as *mut libc::sockaddr,
                    addr_buffer_size
                )
            );
            println!("errno: {}", nix::errno::errno());
        }
        Ok(())
    }

    pub fn send_dhcp_renew(&self) -> Result<(), DhcpError> {
        todo!();
    }

    pub fn recv_dhcp_reply(&self) -> Result<Option<Vec<u8>>, DhcpError> {
        println!("HAHA fd {}", self.fd);
        let mut sender_addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        // TODO: Use iface MTU
        let mut buffer = [0u8; 1500];
        let mut addr_buffer_size: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        let addr_ptr = unsafe {
            std::mem::transmute::<*mut libc::sockaddr_ll, *mut libc::sockaddr>(
                &mut sender_addr,
            )
        };

        unsafe {
            println!("recving");
            println!(
                "recv: {} bytes",
                libc::recvfrom(
                    self.fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0, // flags
                    addr_ptr as *mut libc::sockaddr,
                    &mut addr_buffer_size
                )
            );
        }
        Ok(None)
    }

    pub fn new(iface_name: &str) -> Result<Self, DhcpError> {
        let iface = get_nispor_iface(iface_name)?;
        let iface_index = iface.index as libc::c_int;
        let eth_protocol = libc::ETH_P_ALL;
        let fd = create_raw_socket(eth_protocol)?;
        println!("socket fd is {}", fd);

        bind_raw_socket(fd, eth_protocol, iface_index, &iface.mac_address)?;

        accept_all_mac_address(fd, iface_index)?;

        apply_dhcp_bpf(fd)?;

        Ok(DhcpSocket { fd, iface })
    }
}

fn get_nispor_iface(iface_name: &str) -> Result<Iface, DhcpError> {
    let net_state = match NetState::retrieve() {
        Ok(s) => s,
        Err(e) => {
            return Err(DhcpError::new(
                ErrorKind::Bug,
                format!("Faild to retrieve network state: {}", e),
            ))
        }
    };
    for iface in net_state.ifaces.values() {
        if &iface.name == iface_name {
            return Ok(iface.clone());
        }
    }
    Err(DhcpError::new(
        ErrorKind::InvalidArgument,
        format!("Interface {} not found", iface_name),
    ))
}

fn mac_address_str_to_u8(
    mac_addr: &str,
) -> Result<[u8; libc::ETH_ALEN as usize], DhcpError> {
    let mut data = [0u8; libc::ETH_ALEN as usize];
    let mac_addrs: Vec<&str> = mac_addr.split(":").collect();
    if mac_addrs.len() == libc::ETH_ALEN as usize {
        for i in 0..6 {
            data[i] = match u8::from_str_radix(mac_addrs[i], 16) {
                Ok(d) => d,
                Err(e) => {
                    return Err(DhcpError::new(
                        ErrorKind::Bug,
                        format!("Invalid MAC address {}", mac_addr),
                    ));
                }
            }
        }
        Ok(data)
    } else {
        Err(DhcpError::new(
            ErrorKind::Bug,
            format!("Invalid MAC address {}", mac_addr),
        ))
    }
}

fn accept_all_mac_address(
    fd: libc::c_int,
    iface_index: libc::c_int,
) -> Result<(), DhcpError> {
    let mut mreq = libc::packet_mreq {
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
        .clone_from_slice(&mac_address_str_to_u8(mac_address)?);

    let mut socket_addr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as libc::c_ushort,
        sll_protocol: (eth_protocol as libc::c_ushort).to_be(),
        sll_ifindex: iface_index,
        sll_hatype: libc::ARPHRD_ETHER as libc::c_ushort,
        sll_pkttype: PACKET_HOST as libc::c_uchar,
        sll_halen: libc::ETH_ALEN as libc::c_uchar,
        sll_addr: sll_addr,
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
