// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv4Addr;

use tokio::time::{timeout, Duration};

use super::env::{
    init_log, set_client_ip, with_dhcp_env, with_udhcpd_env, FOO1_HOSTNAME,
    FOO1_STATIC_IP_HOSTNAME_AS_CLIENT_ID, TEST_CLS_DST, TEST_CLS_DST_LEN,
    TEST_CLS_RT_ADDR, TEST_DHCP_SRV_ADDR, TEST_NIC_CLI,
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

#[test]
fn test_dhcpv4_unicast_renew_uses_srv_id() {
    // test with udhcpd from busybox. Its a quite old server implementation
    // but simple and reliable. It does not set siaddr automatically like
    // dnsmasq which makes it a good candidate for a renew test so see that
    // srv_id is used for the unicast renew and not siaddr.
    init_log();

    with_udhcpd_env(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .enable_io()
            .build()
            .unwrap();

        rt.block_on(async {
            let cfg = DhcpV4Config::new(TEST_NIC_CLI);
            let mut cli = DhcpV4Client::init(cfg, None).await.unwrap();

            let lease = loop {
                if let DhcpV4State::Done(l) = cli.run().await.unwrap() {
                    break l;
                }
            };

            assert_eq!(lease.srv_id, TEST_DHCP_SRV_ADDR);
            assert_eq!(lease.yiaddr, Ipv4Addr::new(192, 0, 2, 100));
            set_client_ip(lease.yiaddr);

            // Wait until we are safely past T1 (50% lease time)
            tokio::time::sleep(Duration::from_secs(6)).await;

            // Renew phase
            let state = cli.run().await.unwrap();
            assert_eq!(state, DhcpV4State::Renewing);

            // Observe outcome, timeout is fine, but we should never get so
            // Rebinding (rebinding happens when renew fails,
            // rebinding will use broadcast again like
            // the first discovery)
            let _ = timeout(Duration::from_secs(4), async {
                loop {
                    let state = cli.run().await.unwrap();

                    match state {
                        // Rebinding would happen on T2 = 85% lease time
                        DhcpV4State::Rebinding => {
                            panic!(
                                "entered Rebinding state – Renew via srv_id \
                                 failed"
                            );
                        }
                        DhcpV4State::Renewing => {
                            // still fine, keep polling
                        }
                        other => {
                            log::debug!("Received unused dhcp state: {other:?}")
                        }
                    }
                }
            })
            .await;
        });
    });
}

// RFC 2131 4.4.2: when a previously allocated lease is supplied to
// DhcpV4Client::init(), the client must begin in INIT-REBOOT state and
// broadcast a DHCPREQUEST to verify the lease. A server holding that lease
// confirms it with a DHCPACK, so the client should reuse the very same
// address without falling back to DHCPDISCOVER.
#[test]
fn test_dhcpv4_reboot_confirms_valid_lease() {
    init_log();
    with_dhcp_env(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .enable_io()
            .build()
            .unwrap();

        rt.block_on(async {
            let mut config = DhcpV4Config::new(TEST_NIC_CLI);
            config.set_host_name(FOO1_HOSTNAME);
            config.use_host_name_as_client_id();

            // First acquire a lease the normal way so the server has a
            // record of it.
            let lease = acquire_lease(config.clone()).await;
            assert_eq!(lease.yiaddr, FOO1_STATIC_IP_HOSTNAME_AS_CLIENT_ID);

            // Re-init with the cached lease: the client must verify it via
            // INIT-REBOOT instead of jumping straight into DHCPDISCOVER.
            let mut cli = DhcpV4Client::init(config, Some(lease.clone()))
                .await
                .unwrap();
            assert_eq!(cli.state, DhcpV4State::Rebooting);

            let confirmed = timeout(Duration::from_secs(30), async {
                loop {
                    if let DhcpV4State::Done(l) = cli.run().await.unwrap() {
                        break *l;
                    }
                }
            })
            .await
            .expect("Timed out verifying cached lease via INIT-REBOOT");

            // The server confirmed (DHCPACK) the cached lease, so the same
            // address is kept.
            assert_eq!(confirmed.yiaddr, lease.yiaddr);
            cli.release(&confirmed).await.unwrap();
        });
    })
}

// RFC 2131 4.4.2 / 4.3.2: if the cached lease is no longer valid (here it is
// on the wrong network), the server replies with a DHCPNAK and the client
// must restart the acquisition process from INIT state (DHCPDISCOVER) to
// obtain a fresh lease.
#[test]
fn test_dhcpv4_reboot_falls_back_on_invalid_lease() {
    init_log();
    with_dhcp_env(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .enable_io()
            .build()
            .unwrap();

        rt.block_on(async {
            let mut config = DhcpV4Config::new(TEST_NIC_CLI);
            config.set_host_name(FOO1_HOSTNAME);
            config.use_host_name_as_client_id();

            // Start from a real lease, then move it to a subnet the server
            // does not serve. The server serves 192.0.2.0/24, so an
            // INIT-REBOOT for a 198.51.100.0/24 address must be rejected
            // with a DHCPNAK.
            let mut stale_lease = acquire_lease(config.clone()).await;
            stale_lease.yiaddr = Ipv4Addr::new(198, 51, 100, 50);

            let mut cli = DhcpV4Client::init(config, Some(stale_lease.clone()))
                .await
                .unwrap();
            assert_eq!(cli.state, DhcpV4State::Rebooting);

            let lease = timeout(Duration::from_secs(30), async {
                loop {
                    if let DhcpV4State::Done(l) = cli.run().await.unwrap() {
                        break *l;
                    }
                }
            })
            .await
            .expect("Timed out falling back to DHCPDISCOVER after DHCPNAK");

            // The stale address was rejected, so the client fell back to
            // requesting a brand new lease.
            assert_ne!(lease.yiaddr, stale_lease.yiaddr);
            assert_eq!(lease.yiaddr, FOO1_STATIC_IP_HOSTNAME_AS_CLIENT_ID);
            cli.release(&lease).await.unwrap();
        });
    })
}

// Acquire a DHCP lease through the normal DHCPDISCOVER/DHCPREQUEST flow.
async fn acquire_lease(config: DhcpV4Config) -> DhcpV4Lease {
    let mut cli = DhcpV4Client::init(config, None).await.unwrap();
    loop {
        if let DhcpV4State::Done(lease) = cli.run().await.unwrap() {
            return *lease;
        }
    }
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
