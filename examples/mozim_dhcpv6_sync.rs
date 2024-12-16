// SPDX-License-Identifier: Apache-2.0

use mozim::{DhcpV6Client, DhcpV6Config, DhcpV6IaType};

const TEST_NIC: &str = "dhcpcli";
const POLL_WAIT_TIME: u32 = 5;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_log();
    let mut config =
        DhcpV6Config::new(TEST_NIC, DhcpV6IaType::NonTemporaryAddresses);
    config.set_timeout(60);
    let mut cli = DhcpV6Client::init(config, None).unwrap();

    loop {
        for event in cli.poll(POLL_WAIT_TIME)? {
            if let Some(lease) = cli.process(event)? {
                println!("Got DHCPv6 lease {:?}", lease);
                cli.release(&lease)?;
                return Ok(());
            }
        }
    }
}

fn enable_log() {
    env_logger::Builder::new()
        .filter(Some("nispor"), log::LevelFilter::Debug)
        .filter(Some("mozim"), log::LevelFilter::Debug)
        .init();
}
