// SPDX-License-Identifier: Apache-2.0

use std::process::{Child, Command};

const TEST_DHCPD_NETNS: &str = "mozim_test";
pub(crate) const TEST_NIC_CLI: &str = "dhcpcli";
pub(crate) const TEST_PROXY_MAC1: &str = "00:11:22:33:44:55";
const TEST_NIC_SRV: &str = "dhcpsrv";

const TEST_DHCP_SRV_IP: &str = "192.0.2.1";

pub(crate) const FOO1_STATIC_IP: std::net::Ipv4Addr =
    std::net::Ipv4Addr::new(192, 0, 2, 99);
pub(crate) const TEST_PROXY_IP1: std::net::Ipv4Addr =
    std::net::Ipv4Addr::new(192, 0, 2, 51);

const DNSMASQ_OPTS: &str = r#"
--log-dhcp
--keep-in-foreground
--no-daemon
--conf-file=/dev/null
--dhcp-leasefile=/tmp/mozim_test_dhcpd_lease
--no-hosts
--dhcp-host=foo1,192.0.2.99
--dhcp-host=00:11:22:33:44:55,192.0.2.51
--dhcp-option=option:dns-server,8.8.8.8,1.1.1.1
--dhcp-option=option:mtu,1492
--dhcp-option=option:domain-name,example.com
--dhcp-option=option:ntp-server,192.0.2.1
--keep-in-foreground
--bind-interfaces
--except-interface=lo
--clear-on-reload
--listen-address=192.0.2.1
--dhcp-range=192.0.2.2,192.0.2.50,60 --no-ping
"#;

#[derive(Debug)]
pub(crate) struct DhcpServerEnv {
    daemon: Child,
}

impl DhcpServerEnv {
    pub(crate) fn start() -> Self {
        create_test_net_namespace();
        create_test_veth_nics();
        let daemon = start_dhcp_server();
        Self { daemon }
    }
}

impl Drop for DhcpServerEnv {
    fn drop(&mut self) {
        stop_dhcp_server(&mut self.daemon);
        remove_test_veth_nics();
        remove_test_net_namespace();
    }
}

fn create_test_net_namespace() {
    run_cmd(&format!("ip netns add {TEST_DHCPD_NETNS}"));
}

fn remove_test_net_namespace() {
    run_cmd_ignore_failure(&format!("ip netns del {TEST_DHCPD_NETNS}"));
}

fn create_test_veth_nics() {
    run_cmd(&format!(
        "ip link add {TEST_NIC_CLI} type veth peer name {TEST_NIC_SRV}"
    ));
    run_cmd(&format!("ip link set {TEST_NIC_CLI} up"));
    run_cmd(&format!(
        "ip link set {TEST_NIC_SRV} netns {TEST_DHCPD_NETNS}"
    ));
    run_cmd(&format!(
        "ip netns exec {TEST_DHCPD_NETNS} ip link set {TEST_NIC_SRV} up",
    ));
    run_cmd(&format!(
        "ip netns exec {TEST_DHCPD_NETNS} ip addr add {TEST_DHCP_SRV_IP}/24 dev {TEST_NIC_SRV}",
    ));
}

fn remove_test_veth_nics() {
    run_cmd_ignore_failure(&format!("ip link del {TEST_NIC_CLI}"));
}

fn start_dhcp_server() -> Child {
    let cmd = format!(
        "ip netns exec {} dnsmasq {}",
        TEST_DHCPD_NETNS,
        DNSMASQ_OPTS.replace('\n', " ")
    );
    let cmds: Vec<&str> = cmd.split(' ').collect();
    let mut child = Command::new(cmds[0])
        .args(&cmds[1..])
        .spawn()
        .expect("Failed to start DHCP server");
    std::thread::sleep(std::time::Duration::from_secs(1));
    if let Ok(Some(ret)) = child.try_wait() {
        panic!("Failed to start DHCP server {ret:?}");
    }
    child
}

fn stop_dhcp_server(daemon: &mut Child) {
    daemon.kill().expect("Failed to stop DHCP server")
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
