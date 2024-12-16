// SPDX-License-Identifier: Apache-2.0

use futures::stream::StreamExt;

use mozim::{DhcpV4ClientAsync, DhcpV4Config};

const TEST_NIC: &str = "dhcpcli";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_log();
    let mut config = DhcpV4Config::new(TEST_NIC);
    config.set_host_name("mozim-test");
    config.use_host_name_as_client_id();
    config.set_timeout(60);
    let mut cli = DhcpV4ClientAsync::init(config, None).unwrap();

    loop {
        if let Some(Ok(lease)) = cli.next().await {
            // You need to code to apply the IP address in lease to this NIC, so
            // follow up renew can work.
            println!("Got lease {lease:?}");
            cli.release(&lease)?;
            return Ok(());
        }
    }
}

fn enable_log() {
    env_logger::Builder::new()
        .filter(Some("nispor"), log::LevelFilter::Debug)
        .filter(Some("mozim"), log::LevelFilter::Debug)
        .init();
}
