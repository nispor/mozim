// SPDX-License-Identifier: Apache-2.0

use futures::StreamExt;

use crate::{DhcpV6ClientAsync, DhcpV6Config, DhcpV6IaType, DhcpV6Lease};

use super::env::{with_dhcp_env, FOO1_STATIC_IPV6, TEST_NIC_CLI};

#[test]
fn test_dhcpv6_async() {
    with_dhcp_env(|| {
        let config = DhcpV6Config::new(
            TEST_NIC_CLI,
            DhcpV6IaType::NonTemporaryAddresses,
        );

        let mut cli = DhcpV6ClientAsync::init(config, None).unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();

        let lease = rt.block_on(get_lease(&mut cli));
        assert!(lease.is_some());
        if let Some(lease) = lease {
            // If the client id was set correctly to FOO1_HOSTNAME via the
            // call to use_host_name_as_client_id(), then the server should
            // return FOO1_STATIC_IP_HOSTNAME_AS_CLIENT_ID.
            assert_eq!(lease.addr, FOO1_STATIC_IPV6);
            cli.release(&lease).unwrap();
        }
    })
}

async fn get_lease(cli: &mut DhcpV6ClientAsync) -> Option<DhcpV6Lease> {
    cli.next().await.unwrap().ok()
}
