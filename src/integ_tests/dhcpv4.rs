// SPDX-License-Identifier: Apache-2.0

use crate::{DhcpV4Client, DhcpV4Config, DhcpV4Lease};

use super::env::{
    with_dhcp_env, FOO1_CLIENT_ID, FOO1_HOSTNAME, FOO1_STATIC_IP, TEST_NIC_CLI,
};

const POLL_WAIT_TIME: u32 = 5;

#[test]
fn test_dhcpv4_manual_client_id() {
    with_dhcp_env(|| {
        let mut config = DhcpV4Config::new(TEST_NIC_CLI);
        config.set_client_id(0, FOO1_CLIENT_ID.as_bytes());

        let mut client_id = vec![0];
        client_id.extend_from_slice(FOO1_CLIENT_ID.as_bytes());
        assert_eq!(config.client_id, client_id);

        let mut cli = DhcpV4Client::init(config, None).unwrap();

        let lease = get_lease(&mut cli);

        assert!(lease.is_some());
        if let Some(lease) = lease {
            // Even though we didn't send it in the DHCP request, dnsmasq should
            // return the hostname since it was set in the --dhcp-host
            // option
            assert_eq!(
                lease.host_name.as_ref(),
                Some(&FOO1_HOSTNAME.to_string())
            );
            // If the client id was set correctly to FOO1_CLIENT_ID then the
            // server should return FOO1_STATIC_IP.
            assert_eq!(lease.yiaddr, FOO1_STATIC_IP,);
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
