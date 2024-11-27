// SPDX-License-Identifier: Apache-2.0

use futures::StreamExt;

use crate::{DhcpV4ClientAsync, DhcpV4Config, DhcpV4Lease};

use super::env::{DhcpServerEnv, FOO1_HOSTNAME, FOO1_STATIC_IP_HOSTNAME_AS_CLIENT_ID, TEST_NIC_CLI};

const FOO2_HOSTNAME: &str = "foo2";

#[test]
fn test_dhcpv4_async() {
    let _srv = DhcpServerEnv::start();

    let mut config = DhcpV4Config::new(TEST_NIC_CLI);
    // Since hostname hasn't been set yet, client_id should be empty.
    config.use_host_name_as_client_id();
    assert_eq!(config.client_id.len(), 0);

    config.set_host_name(FOO1_HOSTNAME);
    config.use_host_name_as_client_id();
    // Now client id should be set to 0 + hostname.
    let mut client_id = vec![0];
    client_id.extend_from_slice(FOO1_HOSTNAME.as_bytes());
    assert_eq!(config.client_id, client_id);
    // config.use_host_name_as_client_id() copies the current hostname to client_id
    // at the time it was called.  We should now change the hostname to
    // something dnsmasq doesn't know about so we're sure we get the correct
    // ip address based on the client id (original hostname) and not the
    // hostname we're now sending in option 12.
    config.set_host_name(FOO2_HOSTNAME);

    let mut cli = DhcpV4ClientAsync::init(config, None).unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();

    let lease = rt.block_on(get_lease(&mut cli));
    assert!(lease.is_some());
    if let Some(lease) = lease {
        // We should get FOO2_HOSTNAME as the hostname since that's what we
        // sent in option 12 in the DHCP request.
        assert_eq!(lease.host_name.as_ref(), Some(&FOO2_HOSTNAME.to_string()));
        // If the client id was set correctly to FOO1_HOSTNAME via the
        // call to use_host_name_as_client_id(), then the server should
        // return FOO1_STATIC_IP_HOSTNAME_AS_CLIENT_ID.
        assert_eq!(lease.yiaddr, FOO1_STATIC_IP_HOSTNAME_AS_CLIENT_ID,);
    }
}

async fn get_lease(cli: &mut DhcpV4ClientAsync) -> Option<DhcpV4Lease> {
    cli.next().await.unwrap().ok()
}
