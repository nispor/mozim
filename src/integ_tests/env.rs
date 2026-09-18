// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::VecDeque,
    ffi::CString,
    io::Read,
    net::{Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, OwnedFd},
    process::Command,
    str::FromStr,
    time::{Duration, Instant},
};

use nix::{
    errno::Errno,
    sys::socket::{
        recv, socket, AddressFamily, MsgFlags, SockFlag, SockProtocol, SockType,
    },
};

use crate::dhcpv4::DhcpV4Message;
#[cfg(not(feature = "netlink"))]
use crate::ETH_ALEN;

#[cfg(feature = "netlink")]
const UDHCPD_CONF: &str = "/tmp/mozim_test_udhcpd.conf";
#[cfg(feature = "netlink")]
const UDHCPD_PID_FILE_PATH: &str = "/tmp/mozim_test_udhcpd.pid";
const PID_FILE_PATH: &str = "/tmp/mozim_test_dnsmasq_pid";
const TEST_DHCPD_NETNS: &str = "mozim_test";
const LOG_FILE: &str = "/tmp/mozim_test_dnsmasq_log";
pub(crate) const TEST_NIC_CLI: &str = "dhcpcli";
pub(crate) const TEST_NIC_CLI_MAC: &str = "00:23:45:67:89:1a";
#[cfg(not(feature = "netlink"))]
pub(crate) const TEST_NIC_CLI_MAC_RAW: [u8; ETH_ALEN] =
    [0x00, 0x23, 0x45, 0x67, 0x89, 0x1a];
pub(crate) const TEST_PROXY_MAC1: &str = "00:11:22:33:44:55";
const TEST_NIC_SRV: &str = "dhcpsrv";

const TEST_DHCP_SRV_IP: &str = "192.0.2.1";
#[cfg(feature = "netlink")]
pub(crate) const TEST_DHCP_SRV_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const TEST_DHCP_SRV_IPV6: &str = "2001:db8:a::1";
pub(crate) const TEST_CLS_DST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 0);
pub(crate) const TEST_CLS_DST_LEN: u8 = 24;
pub(crate) const TEST_CLS_RT_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 40);

pub(crate) const FOO1_HOSTNAME: &str = "foo1";
pub(crate) const FOO1_CLIENT_ID: &str =
    "0123456789123456012345678912345601234567891234560123456789123456";

pub(crate) const FOO1_STATIC_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 99);
pub(crate) const FOO1_STATIC_IPV6: Ipv6Addr =
    Ipv6Addr::new(0x2001, 0xdb8, 0xa, 0x0, 0x0, 0x0, 0x0, 0x99);
pub(crate) const FOO1_STATIC_IP_HOSTNAME_AS_CLIENT_ID: Ipv4Addr =
    Ipv4Addr::new(192, 0, 2, 96);
pub(crate) const TEST_PROXY_IP1: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 51);

fn create_test_net_namespace() {
    run_cmd(&format!("ip netns add {TEST_DHCPD_NETNS}"));
}

fn remove_test_net_namespace() {
    run_cmd_ignore_failure(&format!("ip netns del {TEST_DHCPD_NETNS}"));
}

fn create_test_veth_nics() {
    run_cmd(&format!(
        "ip link add {TEST_NIC_CLI} address {TEST_NIC_CLI_MAC} type veth peer \
         name {TEST_NIC_SRV}"
    ));
    run_cmd(&format!("ip link set {TEST_NIC_CLI} up"));
    run_cmd(&format!(
        "ip link set {TEST_NIC_SRV} netns {TEST_DHCPD_NETNS}"
    ));
    run_cmd(&format!(
        "ip netns exec {TEST_DHCPD_NETNS} ip link set {TEST_NIC_SRV} up",
    ));
    run_cmd(&format!(
        "ip netns exec {TEST_DHCPD_NETNS} ip addr add {TEST_DHCP_SRV_IP}/24 \
         dev {TEST_NIC_SRV}",
    ));
    run_cmd(&format!(
        "ip netns exec {TEST_DHCPD_NETNS} ip addr add {TEST_DHCP_SRV_IPV6}/64 \
         dev {TEST_NIC_SRV}",
    ));
    // Need to wait 2 seconds for IPv6 duplicate address detection
    std::thread::sleep(std::time::Duration::from_secs(2));
}

fn remove_test_veth_nics() {
    run_cmd_ignore_failure(&format!("ip link del {TEST_NIC_CLI}"));
}

pub(crate) fn start_dhcp_server() {
    run_cmd(&format!("rm {LOG_FILE}"));
    run_cmd(&format!("touch {LOG_FILE}"));
    run_cmd(&format!("chmod 666 {LOG_FILE}"));

    let dnsmasq_opts = format!(
        r#"
        --pid-file={PID_FILE_PATH}
        --log-queries
        --log-dhcp
        --log-debug
        --log-facility=/tmp/mozim_test_dnsmasq_log
        --conf-file=/dev/null
        --dhcp-leasefile=/tmp/mozim_test_dhcpd_lease
        --no-hosts
        --dhcp-host=id:{FOO1_CLIENT_ID},{FOO1_STATIC_IP},{FOO1_HOSTNAME}
        --dhcp-host=id:00:03:00:01:{TEST_NIC_CLI_MAC},[{FOO1_STATIC_IPV6}],{FOO1_HOSTNAME}
        --dhcp-host=id:{FOO1_HOSTNAME},{FOO1_STATIC_IP_HOSTNAME_AS_CLIENT_ID}
        --dhcp-host={TEST_PROXY_MAC1},{TEST_PROXY_IP1}
        --dhcp-option=option:dns-server,8.8.8.8,1.1.1.1
        --dhcp-option=option:mtu,1492
        --dhcp-option=option:domain-name,example.com
        --dhcp-option=option:ntp-server,192.0.2.1
        --dhcp-option=option6:domain-search,example.com,example.org
        --dhcp-option=option6:ntp-server,ntp.example.com,ntp2.example.com
        --dhcp-option=option6:dns-server,[2001:db8:a::1],[2001:db8:a::2]
        --dhcp-option=121,{TEST_CLS_DST}/{TEST_CLS_DST_LEN},{TEST_CLS_RT_ADDR}
        --dhcp-option=249,{TEST_CLS_DST}/{TEST_CLS_DST_LEN},{TEST_CLS_RT_ADDR}
        --bind-interfaces
        --except-interface=lo
        --clear-on-reload
        --interface=dhcpsrv
        --dhcp-range=192.0.2.2,192.0.2.50,60
        --dhcp-range=2001:db8:a::2,2001:db8:a::ff,64,2m
        --no-ping
        "#
    );

    let cmd = format!(
        "ip netns exec {} dnsmasq {}",
        TEST_DHCPD_NETNS,
        dnsmasq_opts.replace('\n', " ")
    );
    let cmds: Vec<&str> = cmd.split(' ').collect();

    Command::new(cmds[0])
        .args(&cmds[1..])
        .spawn()
        .expect("Failed to start DHCP server")
        .wait()
        .ok();
    // Need to wait 1 seconds for dnsmasq to finish its start
    std::thread::sleep(std::time::Duration::from_secs(1));
}

pub(crate) fn stop_dhcp_server() {
    if !std::path::Path::new(PID_FILE_PATH).exists() {
        return;
    }
    let mut fd = std::fs::File::open(PID_FILE_PATH)
        .unwrap_or_else(|_| panic!("Failed to open {PID_FILE_PATH} file"));
    let mut contents = String::new();
    fd.read_to_string(&mut contents)
        .unwrap_or_else(|_| panic!("Failed to read {PID_FILE_PATH} file"));

    let pid = u32::from_str(contents.trim())
        .unwrap_or_else(|_| panic!("Invalid PID content {contents}"));

    run_cmd_ignore_failure(&format!("kill {pid}"));

    // Wait for dnsmasq to actually exit: tests which start their own DHCP
    // server or observe DHCPDISCOVER retransmissions race with a lingering
    // dnsmasq.
    for _ in 0..100 {
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if rc == -1 && Errno::last() == Errno::ESRCH {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(feature = "netlink")]
fn write_udhcpd_conf() {
    std::fs::write(
        UDHCPD_CONF,
        format!(
            r#"
start       192.0.2.100
end         192.0.2.100
interface   {TEST_NIC_SRV}

option  subnet 255.255.255.0
option  router {TEST_DHCP_SRV_IP}
option  dns    8.8.8.8

lease_file  /tmp/mozim_test_udhcpd.leases
pidfile     /tmp/mozim_test_udhcpd.pid
opt lease   10
no_ping
"#
        ),
    )
    .unwrap();
}

#[cfg(feature = "netlink")]
fn start_udhcpd() {
    write_udhcpd_conf();

    Command::new("ip")
        .args([
            "netns",
            "exec",
            TEST_DHCPD_NETNS,
            "busybox",
            "udhcpd",
            UDHCPD_CONF,
        ])
        .spawn()
        .expect("Failed to start udhcpd")
        .wait()
        .ok();
    // Need to wait 1 seconds for udhcpd to finish its start
    std::thread::sleep(std::time::Duration::from_secs(1));
}

#[cfg(feature = "netlink")]
fn stop_udhcpd() {
    if !std::path::Path::new(UDHCPD_PID_FILE_PATH).exists() {
        log::warn!("PID file {UDHCPD_PID_FILE_PATH} does not exist");
        return;
    }
    let mut fd =
        std::fs::File::open(UDHCPD_PID_FILE_PATH).unwrap_or_else(|_| {
            panic!("Failed to open {UDHCPD_PID_FILE_PATH} file")
        });
    let mut contents = String::new();
    fd.read_to_string(&mut contents).unwrap_or_else(|_| {
        panic!("Failed to read {UDHCPD_PID_FILE_PATH} file")
    });

    let pid = u32::from_str(contents.trim())
        .unwrap_or_else(|_| panic!("Invalid PID content {contents}"));

    run_cmd_ignore_failure(&format!("kill {pid}"));

    run_cmd_ignore_failure("killall udhcpd");
}

fn run_cmd(cmd: &str) -> String {
    let cmds: Vec<&str> = cmd.split(' ').collect();
    String::from_utf8(
        Command::new(cmds[0])
            .args(&cmds[1..])
            .output()
            .unwrap_or_else(|_| panic!("failed to execute command {cmd}"))
            .stdout,
    )
    .expect("Failed to convert file command output to String")
}

fn run_cmd_ignore_failure(cmd: &str) -> String {
    let cmds: Vec<&str> = cmd.split(' ').collect();

    match Command::new(cmds[0]).args(&cmds[1..]).output() {
        Ok(o) => String::from_utf8(o.stdout).unwrap_or_default(),
        Err(e) => {
            eprintln!("Failed to execute command {cmd}: {e}");
            "".to_string()
        }
    }
}

#[cfg(not(feature = "netlink"))]
pub(crate) fn get_iface_index(iface_name: &str) -> u32 {
    let output = run_cmd(&format!("ip -o link show {iface_name}"));
    output
        .split(':')
        .next()
        .unwrap_or_else(|| {
            panic!("Failed to get interface index of {iface_name}: {output}")
        })
        .trim()
        .parse()
        .unwrap_or_else(|_| {
            panic!("Failed to parse interface index of {iface_name}: {output}")
        })
}

#[cfg(not(feature = "netlink"))]
pub(crate) fn get_link_local_addr(iface_name: &str) -> Ipv6Addr {
    let output =
        run_cmd(&format!("ip -6 addr show dev {iface_name} scope link"));
    let line = output
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("inet6 "))
        .unwrap_or_else(|| {
            panic!("No link-local address found for {iface_name}: {output}")
        });
    let addr = line.trim_start_matches("inet6 ").split('/').next().unwrap();
    Ipv6Addr::from_str(addr).unwrap_or_else(|_| {
        panic!("Invalid link-local address {addr} of {iface_name}")
    })
}

#[cfg(feature = "netlink")]
pub(crate) fn set_client_ip(address: Ipv4Addr) {
    run_cmd(&format!("ip addr add {address}/24 dev {TEST_NIC_CLI}",));
}

#[cfg(feature = "netlink")]
pub(crate) fn set_client_nic_down() {
    run_cmd(&format!("ip link set {TEST_NIC_CLI} down"));
}

pub(crate) fn with_dhcp_env<T>(test: T)
where
    T: FnOnce() + std::panic::UnwindSafe,
{
    create_test_net_namespace();
    create_test_veth_nics();
    stop_dhcp_server();
    start_dhcp_server();

    let result = std::panic::catch_unwind(|| {
        test();
    });

    stop_dhcp_server();
    remove_test_veth_nics();
    remove_test_net_namespace();
    assert!(result.is_ok())
}

/// Same as [with_dhcp_env()] except that the DHCP server is not started, so
/// tests can control when the server becomes available.
pub(crate) fn with_dhcp_env_no_server<T>(test: T)
where
    T: FnOnce() + std::panic::UnwindSafe,
{
    create_test_net_namespace();
    create_test_veth_nics();
    stop_dhcp_server();

    let result = std::panic::catch_unwind(|| {
        test();
    });

    stop_dhcp_server();
    remove_test_veth_nics();
    remove_test_net_namespace();
    assert!(result.is_ok())
}

#[cfg(feature = "netlink")]
pub(crate) fn with_udhcpd_env<T>(test: T)
where
    T: FnOnce() + std::panic::UnwindSafe,
{
    create_test_net_namespace();
    create_test_veth_nics();

    stop_udhcpd();
    start_udhcpd();

    let result = std::panic::catch_unwind(test);

    stop_udhcpd();
    remove_test_veth_nics();
    remove_test_net_namespace();

    assert!(result.is_ok());
}

pub(crate) fn init_log() {
    let mut log_builder = env_logger::Builder::new();
    log_builder.filter(Some("mozim"), log::LevelFilter::Trace);
    log_builder.try_init().ok();
}

/// Captures DHCPv4 messages sent and received on a network interface.
///
/// The `DhcpV4Client` raw socket only receives DHCP replies (UDP
/// destination port 68), so tests which need to check the DHCPDISCOVER and
/// DHCPREQUEST messages sent by the client require their own AF_PACKET
/// socket, which also sees outgoing frames.
pub(crate) struct DhcpV4Sniffer {
    fd: OwnedFd,
    pending: VecDeque<DhcpV4Message>,
}

impl DhcpV4Sniffer {
    pub(crate) fn new(iface_name: &str) -> Self {
        let fd = socket(
            AddressFamily::Packet,
            SockType::Raw,
            SockFlag::SOCK_NONBLOCK,
            Some(SockProtocol::EthAll),
        )
        .expect("Failed to create raw packet socket for DHCP sniffer");

        let iface_index = unsafe {
            let iface_name = CString::new(iface_name).unwrap();
            libc::if_nametoindex(iface_name.as_ptr())
        };
        assert_ne!(iface_index, 0, "Failed to get {iface_name} index");

        let mut socket_addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as libc::c_ushort,
            sll_protocol: (libc::ETH_P_ALL as libc::c_ushort).to_be(),
            sll_ifindex: iface_index as libc::c_int,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&mut socket_addr as *mut libc::sockaddr_ll)
                    .cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "Failed to bind DHCP sniffer to {iface_name}");

        Self {
            fd,
            pending: VecDeque::new(),
        }
    }

    /// Return the next DHCPv4 message on the interface, or `None` when
    /// `timeout` expired. Frames which are not DHCPv4 are skipped.
    pub(crate) fn recv_timeout(
        &mut self,
        timeout: Duration,
    ) -> Option<DhcpV4Message> {
        if let Some(msg) = self.pending.pop_front() {
            return Some(msg);
        }
        let deadline = Instant::now() + timeout;
        loop {
            let mut poll_fd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let remains = deadline.saturating_duration_since(Instant::now());
            let rc = unsafe {
                libc::poll(&mut poll_fd, 1, remains.as_millis() as libc::c_int)
            };
            if rc == -1 && Errno::last() == Errno::EINTR {
                continue;
            }
            assert!(rc >= 0, "Failed to poll DHCP sniffer socket");
            if poll_fd.revents & libc::POLLIN == 0 {
                return None;
            }

            let mut buffer = [0u8; 1500];
            loop {
                match recv(self.fd.as_raw_fd(), &mut buffer, MsgFlags::empty())
                {
                    Ok(received) => {
                        if let Ok(msg) =
                            DhcpV4Message::parse_eth_packet(&buffer[..received])
                        {
                            self.pending.push_back(msg);
                        }
                    }
                    Err(Errno::EAGAIN) => break,
                    Err(e) => panic!("Failed to receive packet: {e}"),
                }
            }
            // Several DHCP messages may be received in one batch, e.g. the
            // DHCPDISCOVER and the following DHCPREQUEST of the same
            // exchange, queue them instead of dropping any.
            if let Some(msg) = self.pending.pop_front() {
                return Some(msg);
            }
        }
    }
}
