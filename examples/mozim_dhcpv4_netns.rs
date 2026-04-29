// SPDX-License-Identifier: Apache-2.0

use mozim::{DhcpV4Client, DhcpV4Config, DhcpV4State};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_log();

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        let msg = format!(
            "Usage: {} <iface> <proxy-mac> <iface-index> <netns-path>",
            args[0],
        );
        return Err(
            std::io::Error::new(std::io::ErrorKind::InvalidInput, msg).into()
        );
    }

    let iface_index = args[3].parse::<u32>()?;
    let mut config = DhcpV4Config::new_proxy(&args[1], &args[2])?;
    config.set_iface_index(iface_index);
    config.set_socket_netns_path(Some(args[4].clone()));
    config.set_timeout_sec(300);

    let mut cli = DhcpV4Client::init(config, None).await.unwrap();
    let mut got_lease = None;

    loop {
        if let Ok(state) = cli.run().await {
            println!("DHCP state {state}");
            if let DhcpV4State::Done(lease) = state {
                println!("Got lease {lease:?}");
                got_lease = Some(lease);
                continue;
            }
            if state == DhcpV4State::Rebinding {
                if let Some(lease) = got_lease.as_ref() {
                    cli.release(lease).await?;
                    println!("DHCP lease released");
                    return Ok(());
                }
            }
        }
    }
}

fn enable_log() {
    env_logger::Builder::new()
        .filter(Some("mozim"), log::LevelFilter::Trace)
        .init();
}
