// SPDX-License-Identifier: Apache-2.0

use mozim::{DhcpV4Client, DhcpV4Config, DhcpV4State};

const TEST_NIC: &str = "dhcpcli";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_log();
    let mut config = DhcpV4Config::new(TEST_NIC);
    config.set_host_name("mozim-test");
    config.use_host_name_as_client_id();
    config.set_timeout_sec(300);
    let mut cli = DhcpV4Client::init(config, None).await.unwrap();
    let mut got_lease = None;

    loop {
        let state = cli.run().await?;
        println!("DHCP state {state}");
        if let DhcpV4State::Done(lease) = state {
            println!("Got lease {lease:?}");
            got_lease = Some(lease);
            continue;
        }
        // We did not assign IP to interface, so the renew and rebind
        // will fail. Just release the lease on rebind state.
        if state == DhcpV4State::Rebinding {
            if let Some(lease) = got_lease.as_ref() {
                cli.release(lease).await?;
                println!("DHCP lease released");
                return Ok(());
            }
        }
    }
}

fn enable_log() {
    env_logger::Builder::new()
        .filter(Some("mozim"), log::LevelFilter::Trace)
        .init();
}
