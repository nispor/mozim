use mozim::{DhcpV4Client, DhcpV4Config, DhcpV4Lease};
use nispor::{IfaceConf, IfaceState, IpAddrConf, IpConf, NetConf};

fn main() {
    let mut log_builder = env_logger::Builder::new();
    log_builder.filter(Some("mozim"), log::LevelFilter::Debug);
    log_builder.init();

    let mut config = DhcpV4Config::new("eth1").unwrap();
    config.set_host_name("Gris-Laptop");
    config.use_host_name_as_client_id();
    let mut cli = DhcpV4Client::new(config);

    let mut lease = cli.request(None).unwrap();

    println!("Got lease {:?}", lease);
    apply_dhcp_ip("eth1", &lease);

    loop {
        match cli.run(&lease) {
            Ok(l) => {
                println!("new lease {:?}", l);
                apply_dhcp_ip("eth1", &l);
                lease = l;
            }
            Err(e) => {
                println!("error {:?}", e);
                break;
            }
        }
    }
}

fn apply_dhcp_ip(iface_name: &str, lease: &DhcpV4Lease) {
    let mut ip_addr_conf = IpAddrConf::default();
    ip_addr_conf.address = lease.yiaddr.to_string();
    ip_addr_conf.prefix_len = get_prefix_len(&lease.subnet_mask);
    ip_addr_conf.valid_lft = format!("{}sec", lease.lease_time);
    ip_addr_conf.preferred_lft = format!("{}sec", lease.lease_time);
    let mut ip_conf = IpConf::default();
    ip_conf.addresses = vec![ip_addr_conf];
    let mut iface_conf = IfaceConf::default();
    iface_conf.name = iface_name.to_string();
    iface_conf.state = IfaceState::Up;
    iface_conf.ipv4 = Some(ip_conf);
    let mut net_conf = NetConf::default();
    net_conf.ifaces = Some(vec![iface_conf]);
    net_conf.apply().unwrap();
}

fn get_prefix_len(ip: &std::net::Ipv4Addr) -> u8 {
    u32::from_be_bytes(ip.octets()).count_ones() as u8
}
