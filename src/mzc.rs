use mozim::{DhcpV4Client, DhcpV4Config, DhcpV4Lease};
use nispor::{IfaceConf, IfaceState, IpAddrConf, IpConf, NetConf};

fn main() {
    let mut log_builder = env_logger::Builder::new();
    log_builder.filter(Some("mozim"), log::LevelFilter::Debug);
    log_builder.init();

    let mut config = DhcpV4Config::new("eth1").unwrap();
    config.set_host_name("Gris-Laptop");
    config.use_host_name_as_client_id();
    let cli = DhcpV4Client::new(config);

    let lease = cli.request(None).unwrap();

    println!("Got lease {:?}", lease);
    apply_dhcp_ip("eth1", &lease);

    loop {
        match cli.run(&lease) {
            Ok(lease) => {
                println!("new lease {:?}", lease);
            }

            Err(e) => {
                println!("error {:?}", e);
                break;
            }
        }
    }
}

fn apply_dhcp_ip(iface_name: &str, lease: &DhcpV4Lease) {
    let ifaces = Some(vec![IfaceConf {
        name: iface_name.to_string(),
        state: IfaceState::Up,
        ipv4: Some(IpConf {
            addresses: vec![IpAddrConf {
                address: lease.yiaddr.to_string(),
                prefix_len: get_prefix_len(&lease.subnet_mask),
                valid_lft: format!("{}sec", lease.lease_time),
                preferred_lft: format!("{}sec", lease.lease_time),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    }]);
    NetConf { ifaces }.apply().unwrap();
}

fn get_prefix_len(ip: &std::net::Ipv4Addr) -> u8 {
    u32::from_be_bytes(ip.octets()).count_ones() as u8
}
