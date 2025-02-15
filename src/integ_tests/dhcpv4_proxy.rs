// SPDX-License-Identifier: Apache-2.0

use crate::{DhcpV4Client, DhcpV4Config, DhcpV4Lease};

use super::env::{
    with_dhcp_env, TEST_NIC_CLI, TEST_PROXY_IP1, TEST_PROXY_MAC1,
};

const POLL_WAIT_TIME: u32 = 5;

#[test]
fn test_dhcpv4_proxy() {
    with_dhcp_env(|| {
        let config = DhcpV4Config::new_proxy(TEST_NIC_CLI, TEST_PROXY_MAC1);
        let mut cli = DhcpV4Client::init(config, None).unwrap();

        let lease = get_lease(&mut cli);
        assert!(lease.is_some());
        if let Some(lease) = lease {
            assert_eq!(lease.yiaddr, TEST_PROXY_IP1);
            cli.release(&lease).unwrap();
        }
    })
}

fn get_lease(cli: &mut DhcpV4Client) -> Option<DhcpV4Lease> {
    while let Ok(events) = cli.poll(POLL_WAIT_TIME) {
        for event in events {
            match cli.process(event) {
                Ok(Some(lease)) => {
                    return Some(lease);
                }
                Ok(None) => (),
                Err(_) => {
                    return None;
                }
            }
        }
    }
    None
}
