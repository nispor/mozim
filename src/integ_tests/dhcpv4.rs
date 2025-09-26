// SPDX-License-Identifier: Apache-2.0

use super::env::{
    init_log, with_dhcp_env, FOO1_HOSTNAME,
    FOO1_STATIC_IP_HOSTNAME_AS_CLIENT_ID, TEST_CLS_DST, TEST_CLS_DST_LEN,
    TEST_CLS_RT_ADDR, TEST_NIC_CLI,
};
use crate::{
    DhcpV4ClasslessRoute, DhcpV4Client, DhcpV4Config, DhcpV4Lease, DhcpV4State,
};

const FOO2_HOSTNAME: &str = "foo2";

#[test]
fn test_dhcpv4() {
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
            // We should get FOO2_HOSTNAME as the hostname since that's what we
            // sent in option 12 in the DHCP request.
            assert_eq!(
                lease.host_name.as_ref(),
                Some(&FOO2_HOSTNAME.to_string())
            );
            // If the client id was set correctly to FOO1_HOSTNAME via the
            // call to use_host_name_as_client_id(), then the server should
            // return FOO1_STATIC_IP_HOSTNAME_AS_CLIENT_ID.
            assert_eq!(lease.yiaddr, FOO1_STATIC_IP_HOSTNAME_AS_CLIENT_ID,);

            assert_eq!(
                lease.classless_routes.as_deref().unwrap(),
                &[DhcpV4ClasslessRoute {
                    destination: TEST_CLS_DST,
                    prefix_length: TEST_CLS_DST_LEN,
                    router: TEST_CLS_RT_ADDR,
                }]
            );

            assert_eq!(
                lease.get_option_raw(249).unwrap(),
                &[249, 8, 24, 203, 0, 113, 192, 0, 2, 40]
            );
        }
    })
}

async fn get_lease() -> Option<DhcpV4Lease> {
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
    // config.use_host_name_as_client_id() copies the current hostname to
    // client_id at the time it was called.  We should now change the
    // hostname to something dnsmasq doesn't know about so we're sure we get
    // the correct ip address based on the client id (original hostname) and
    // not the hostname we're now sending in option 12.
    config.set_host_name(FOO2_HOSTNAME);

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
