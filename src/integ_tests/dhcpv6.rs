// SPDX-License-Identifier: Apache-2.0

use super::env::{init_log, with_dhcp_env, FOO1_STATIC_IPV6, TEST_NIC_CLI};
use crate::{DhcpV6Client, DhcpV6Config, DhcpV6Lease, DhcpV6Mode, DhcpV6State};

#[test]
fn test_dhcpv6() {
    init_log();
    with_dhcp_env(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .enable_io()
            .build()
            .unwrap();

        let lease = rt.block_on(get_lease());
        assert!(lease.is_some());
        if let Some(lease) = lease {
            // If the client id was set correctly to FOO1_HOSTNAME via the
            // call to use_host_name_as_client_id(), then the server should
            // return FOO1_STATIC_IP_HOSTNAME_AS_CLIENT_ID.
            assert_eq!(lease.address, FOO1_STATIC_IPV6);
        }
    })
}

async fn get_lease() -> Option<DhcpV6Lease> {
    let config =
        DhcpV6Config::new(TEST_NIC_CLI, DhcpV6Mode::NonTemporaryAddresses);
    let mut cli = DhcpV6Client::init(config, None).await.unwrap();

    while let Ok(state) = cli.run().await {
        if let DhcpV6State::Done(lease) = state {
            cli.release(&lease).await.unwrap();
            return Some(*lease);
        } else {
            println!("DHCP state {state}");
        }
    }
    None
}
