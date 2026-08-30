// SPDX-License-Identifier: Apache-2.0

use super::env::{
    get_iface_index, get_link_local_addr, init_log, with_dhcp_env,
    FOO1_HOSTNAME, FOO1_STATIC_IPV6, FOO1_STATIC_IP_HOSTNAME_AS_CLIENT_ID,
    TEST_CLS_DST, TEST_CLS_DST_LEN, TEST_CLS_RT_ADDR, TEST_NIC_CLI,
    TEST_NIC_CLI_MAC_RAW,
};
use crate::{
    DhcpV4ClasslessRoute, DhcpV4Client, DhcpV4Config, DhcpV4Lease, DhcpV4State,
    DhcpV6Client, DhcpV6Config, DhcpV6Lease, DhcpV6Mode, DhcpV6State,
};

const FOO2_HOSTNAME: &str = "foo2";

#[test]
fn test_dhcpv4_no_netlink() {
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
            assert_eq!(
                lease.host_name.as_ref(),
                Some(&FOO2_HOSTNAME.to_string())
            );
            assert_eq!(lease.yiaddr, FOO1_STATIC_IP_HOSTNAME_AS_CLIENT_ID);
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

#[test]
fn test_dhcpv6_no_netlink() {
    init_log();
    with_dhcp_env(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .enable_io()
            .build()
            .unwrap();

        let lease = rt.block_on(get_v6_lease());
        assert!(lease.is_some());
        if let Some(lease) = lease {
            assert_eq!(lease.address, FOO1_STATIC_IPV6);
            assert_eq!(
                lease.domain_list,
                vec!["example.com".to_string(), "example.org".to_string()]
            );
            assert_eq!(
                lease.ntp_srvs,
                vec![
                    "ntp.example.com".to_string(),
                    "ntp2.example.com".to_string(),
                ]
            );
        }
    })
}

async fn get_lease() -> Option<DhcpV4Lease> {
    let mut config = DhcpV4Config::new(TEST_NIC_CLI);
    config.set_iface_index(get_iface_index(TEST_NIC_CLI));
    config.set_iface_mac_raw(&TEST_NIC_CLI_MAC_RAW).unwrap();
    config.use_host_name_as_client_id();
    assert_eq!(config.client_id.len(), 0);

    config.set_host_name(FOO1_HOSTNAME);
    config.use_host_name_as_client_id();
    let mut client_id = vec![0];
    client_id.extend_from_slice(FOO1_HOSTNAME.as_bytes());
    assert_eq!(config.client_id, client_id);
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

async fn get_v6_lease() -> Option<DhcpV6Lease> {
    let mut config =
        DhcpV6Config::new(TEST_NIC_CLI, DhcpV6Mode::NonTemporaryAddresses);
    config.set_iface_index(get_iface_index(TEST_NIC_CLI));
    config.set_link_local_ip(get_link_local_addr(TEST_NIC_CLI));
    config.set_duid_by_iface_mac(&TEST_NIC_CLI_MAC_RAW);
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
