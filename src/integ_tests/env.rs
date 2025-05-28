// SPDX-License-Identifier: Apache-2.0

use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::str::FromStr;

const PID_FILE_PATH: &str = "/tmp/mozim_test_dnsmasq_pid";
const TEST_DHCPD_NETNS: &str = "mozim_test";
const LOG_FILE: &str = "/tmp/mozim_test_dnsmasq_log";
pub(crate) const TEST_NIC_CLI: &str = "dhcpcli";
const TEST_NIC_CLI_MAC: &str = "00:23:45:67:89:1a";
pub(crate) const TEST_PROXY_MAC1: &str = "00:11:22:33:44:55";
const TEST_NIC_SRV: &str = "dhcpsrv";

const TEST_DHCP_SRV_IP: &str = "192.0.2.1";
const TEST_DHCP_SRV_IPV6: &str = "2001:db8:a::1";

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

fn start_dhcp_server() {
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

fn stop_dhcp_server() {
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
