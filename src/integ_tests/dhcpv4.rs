// SPDX-License-Identifier: Apache-2.0

use crate::{DhcpV4Client, DhcpV4Config, DhcpV4Lease};

use super::env::{DhcpServerEnv, FOO1_STATIC_IP, TEST_NIC_CLI};

const POLL_WAIT_TIME: isize = 5;

#[test]
fn test_dhcpv4_manual_client_id() {
    let _srv = DhcpServerEnv::start();

    let mut config = DhcpV4Config::new(TEST_NIC_CLI).unwrap();
    config.set_host_name("foo1");
    config.use_host_name_as_client_id();
    let mut cli = DhcpV4Client::init(config, None).unwrap();

    let lease = get_lease(&mut cli);
    assert!(lease.is_some());
    if let Some(lease) = lease {
        assert_eq!(lease.host_name.as_ref(), Some(&"foo1".to_string()));
        assert_eq!(lease.yiaddr, FOO1_STATIC_IP,);
    }
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
