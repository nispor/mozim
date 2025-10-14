# Mozim -- DHCP Client Library

Example code:

```rust
use mozim::{DhcpV4Client, DhcpV4Config, DhcpV4State};

const TEST_NIC: &str = "dhcpcli";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = DhcpV4Config::new(TEST_NIC);
    config.set_host_name("mozim-test");
    config.use_host_name_as_client_id();
    config.set_timeout_sec(300);
    let mut cli = DhcpV4Client::init(config, None).await?;
    let mut got_lease = None;

    loop {
        let state = cli.run().await?;
        println!("DHCP state {state}");
        if let DhcpV4State::Done(lease) = state {
            println!("Got DHCPv4 lease {lease:?}");
            got_lease = Some(lease);
        } else {
            println!("DHCPv4 on {TEST_NIC} enter {state}");
        }
    }
}
```

# Try out

```bash
# Below script will create veth eth1/eth1.ep.
# The `eth1.ep` is DHCP server interface running dnsmasq in `mozim` network
# namespace.
sudo ./utils/test_env_mozim &
cargo run --example mozim_dhcpv4
cargo run --example mozim_dhcpv6
```
