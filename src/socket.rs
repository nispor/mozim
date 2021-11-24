use etherparse::PacketBuilder;
use std::ffi::CString;
use std::io::Write;
use std::net::Ipv4Addr;
use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;

use libc;
use nispor::{Iface, NetState};
use nix;

use crate::{
    bpf::apply_dhcp_bpf, dhcp_msg::Dhcp4Message, mac::mac_str_to_u8_array,
    DhcpError, Emitable, ErrorKind,
};

const PACKET_HOST: u8 = 0; // a packet addressed to the local host
const BROADCAST_MAC: &str = "ff:ff:ff:ff:ff:ff";

const DEFAULT_TTL: u8 = 128;

pub struct DhcpSocket {
    raw_fd: libc::c_int,
    iface: Iface,
}

impl std::os::unix::io::AsRawFd for DhcpSocket {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.raw_fd as std::os::unix::io::RawFd
    }
}

impl DhcpSocket {
    pub fn close(&self) {
        if self.raw_fd >= 0 {
            unsafe {
                libc::close(self.raw_fd);
            }
        }
    }

    pub fn send_dhcp_discovery(
        &self,
        host_name: &str,
    ) -> Result<(), DhcpError> {
        let mut dhcp_msg_bytes = Dhcp4Message::new()
            .set_host_name(host_name)?
            .set_hw_addr(&self.iface.mac_address)?
            .client_identifier_use_mac()
            .dhcp_discovery()
            .to_bytes()?;

        let mut eth_pkg = gen_eth_pkg(
            &self.iface.mac_address,
            BROADCAST_MAC,
            &Ipv4Addr::new(0, 0, 0, 0),
            &Ipv4Addr::new(255, 255, 255, 255),
            dhcproto::v4::CLIENT_PORT,
            dhcproto::v4::SERVER_PORT,
            &dhcp_msg_bytes,
        )?;

        let mut sender_addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sender_addr.sll_halen = libc::ETH_ALEN as u8;

        sender_addr.sll_addr[..libc::ETH_ALEN as usize].clone_from_slice(
            &mac_address_to_eth_mac_bytes("ff:ff:ff:ff:ff:ff")?,
        );
        sender_addr.sll_ifindex = self.iface.index as i32;
        let addr_buffer_size: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        let addr_ptr = unsafe {
            std::mem::transmute::<*mut libc::sockaddr_ll, *mut libc::sockaddr>(
                &mut sender_addr,
            )
        };

        unsafe {
            dump_pkg(&eth_pkg);
            println!(
                "sent: {} bytes",
                libc::sendto(
                    self.raw_fd,
                    eth_pkg.as_mut_ptr() as *mut libc::c_void,
                    eth_pkg.len(),
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
        println!("HAHA fd {}", self.raw_fd);
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
                    self.raw_fd,
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
        let raw_fd = create_raw_socket(eth_protocol)?;
        println!("socket raw_fd is {}", raw_fd);

        bind_raw_socket(raw_fd, eth_protocol, iface_index, &iface.mac_address)?;

        accept_all_mac_address(raw_fd, iface_index)?;

        apply_dhcp_bpf(raw_fd)?;

        Ok(DhcpSocket { raw_fd, iface })
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
        .clone_from_slice(&mac_address_to_eth_mac_bytes(mac_address)?);

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

fn gen_eth_pkg(
    src_mac: &str,
    dst_mac: &str,
    src_ip: &Ipv4Addr,
    dst_ip: &Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, DhcpError> {
    let src_mac = mac_address_to_eth_mac_bytes(src_mac)?;
    let dst_mac = mac_address_to_eth_mac_bytes(dst_mac)?;
    let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
        .ipv4(src_ip.octets(), dst_ip.octets(), DEFAULT_TTL)
        .udp(src_port, dst_port);

    let mut pkg = Vec::<u8>::with_capacity(builder.size(payload.len()));

    builder.write(&mut pkg, &payload)?;

    Ok(pkg)
}

fn mac_address_to_eth_mac_bytes(
    mac_address: &str,
) -> Result<[u8; libc::ETH_ALEN as usize], DhcpError> {
    let mut ret = [0u8; libc::ETH_ALEN as usize];
    let mac_bytes = mac_str_to_u8_array(mac_address);

    if mac_bytes.len() > libc::ETH_ALEN as usize {
        Err(DhcpError::new(
            ErrorKind::Bug,
            format!(
                "MAC address {} exceeded the max length {}",
                mac_address,
                libc::ETH_ALEN
            ),
        ))
    } else {
        ret.clone_from_slice(&mac_bytes);
        Ok(ret)
    }
}

fn dump_pkg(pkg: &[u8]) {
    let mut i = 0;
    for oct in pkg {
        print!("{:02x} ", oct);
        if i % 16 == 7 {
            print!(" ");
        } else if i % 16 == 15 {
            println!("");
        }
        i += 1;
    }
    println!("");
}
