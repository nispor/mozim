// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use super::env::{
    init_log, set_client_nic_down, with_dhcp_env, TEST_NIC_CLI, TEST_PROXY_IP1,
    TEST_PROXY_MAC1,
};
use crate::{DhcpV4Client, DhcpV4Config, DhcpV4Lease, DhcpV4State};

#[test]
fn test_dhcpv4_proxy() {
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
            assert_eq!(lease.yiaddr, TEST_PROXY_IP1);
        }
    })
}

#[test]
fn test_dhcpv4_proxy_release_error_on_down_iface() {
    init_log();
    with_dhcp_env(|| {
        let (tx, rx) = std::sync::mpsc::channel();
        // The release runs on its own thread: the pre-fix `send()`
        // spins forever on the discarded error, which would starve
        // any tokio timeout on a current-thread runtime. This way
        // the test fails with `recv_timeout()` instead of hanging.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .enable_io()
                .build()
                .unwrap();
            let result = rt.block_on(async {
                let config =
                    DhcpV4Config::new_proxy(TEST_NIC_CLI, TEST_PROXY_MAC1)
                        .unwrap();
                let mut cli = DhcpV4Client::init(config, None).await.unwrap();

                let lease = loop {
                    if let DhcpV4State::Done(l) = cli.run().await.unwrap() {
                        break l;
                    }
                };

                set_client_nic_down();

                cli.release(&lease).await
            });
            let _ = tx.send(result);
        });

        let result = rx.recv_timeout(Duration::from_secs(20));
        // Before the fix, `DhcpRawSocket::send()` discarded the
        // send error and kept spinning, so no result ever arrived.
        assert!(matches!(result, Ok(Err(_))));
    })
}

async fn get_lease() -> Option<DhcpV4Lease> {
    let config =
        DhcpV4Config::new_proxy(TEST_NIC_CLI, TEST_PROXY_MAC1).unwrap();
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
