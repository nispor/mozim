// SPDX-License-Identifier: Apache-2.0

use super::env::{
    init_log, test_client_iface_index, with_dhcp_client_netns_env,
    TEST_DHCP_CLI_NETNS_PATH, TEST_NIC_CLI, TEST_PROXY_IP1, TEST_PROXY_MAC1,
};
use crate::{DhcpV4Client, DhcpV4Config, DhcpV4Lease, DhcpV4State};

#[test]
fn test_dhcpv4_proxy_socket_netns() {
    init_log();
    with_dhcp_client_netns_env(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .enable_io()
            .build()
            .unwrap();

        let lease = rt.block_on(get_lease());

        assert!(lease.is_some());
        if let Some(lease) = lease {
            assert_eq!(lease.yiaddr, TEST_PROXY_IP1);
        }
    })
}

async fn get_lease() -> Option<DhcpV4Lease> {
    let mut config =
        DhcpV4Config::new_proxy(TEST_NIC_CLI, TEST_PROXY_MAC1).unwrap();
    config.set_iface_index(test_client_iface_index());
    config.set_socket_netns_path(Some(TEST_DHCP_CLI_NETNS_PATH.to_string()));
    config.set_timeout_sec(5);

    let mut cli = DhcpV4Client::init(config, None).await.unwrap();

    while let Ok(state) = cli.run().await {
        if let DhcpV4State::Done(lease) = state {
            cli.release(&lease).await.unwrap();
            return Some(*lease);
        } else {
            println!("DHCP state {state}");
        }
    }
    None
}
