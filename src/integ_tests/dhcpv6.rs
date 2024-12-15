// SPDX-License-Identifier: Apache-2.0

use crate::{DhcpV6Client, DhcpV6Config, DhcpV6IaType, DhcpV6Lease};

use super::env::{with_dhcp_env, FOO1_STATIC_IPV6, TEST_NIC_CLI};

const POLL_WAIT_TIME: u32 = 5;

#[test]
fn test_dhcpv6_use_default_client_id() {
    with_dhcp_env(|| {
        let config = DhcpV6Config::new(
            TEST_NIC_CLI,
            DhcpV6IaType::NonTemporaryAddresses,
        );
        let mut cli = DhcpV6Client::init(config, None).unwrap();

        let lease = get_lease(&mut cli);
        println!("Got lease {:?}", lease);
        assert!(lease.is_some());
        if let Some(lease) = lease {
            assert_eq!(lease.addr, FOO1_STATIC_IPV6);
        }
    })
}

fn get_lease(cli: &mut DhcpV6Client) -> Option<DhcpV6Lease> {
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
