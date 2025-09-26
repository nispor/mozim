// SPDX-License-Identifier: Apache-2.0

use mozim::{DhcpV6Client, DhcpV6Config, DhcpV6Mode, DhcpV6State};

const TEST_NIC: &str = "dhcpcli";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_log();
    let mut config =
        DhcpV6Config::new(TEST_NIC, DhcpV6Mode::new_non_temp_addr());
    config.set_timeout_sec(1);
    let mut cli = DhcpV6Client::init(config, None).await.unwrap();
    let mut got_lease = None;

    loop {
        let state = cli.run().await?;
        if got_lease.is_none() {
            println!("DHCP state {state}");
            if let DhcpV6State::Done(lease) = state {
                println!("Got lease {lease:?}");
                got_lease = Some(lease);
                continue;
            }
        } else if let DhcpV6State::Done(_) = state {
            // Release the lease after renew finished.
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
