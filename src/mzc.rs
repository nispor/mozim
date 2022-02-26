use clap::Parser;
use mozim::{DhcpV4Client, DhcpV4Config, DhcpV4Lease};
use nispor::{IfaceConf, IfaceState, IpAddrConf, IpConf, NetConf, NetState};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = "DHCPv4 Client")]
struct Args {
    iface: String,
}

fn main() {
    let args = Args::parse();

    let iface_name = args.iface.as_str();

    let mut log_builder = env_logger::Builder::new();
    log_builder.filter(Some("mozim"), log::LevelFilter::Debug);
    log_builder.init();

    let mut config = DhcpV4Config::new(iface_name).unwrap();
    config.set_host_name("Gris-Laptop");
    config.use_host_name_as_client_id();
    let mut cli = DhcpV4Client::new(config);

    let mut lease = cli.request(None).unwrap();

    println!("Got lease {:?}", lease);
    apply_dhcp_ip_route(iface_name, &lease);

    loop {
        match cli.run(&lease) {
            Ok(l) => {
                println!("new lease {:?}", l);
                apply_dhcp_ip_route(iface_name, &l);
                lease = l;
            }
            Err(e) => {
                println!("error {:?}", e);
                purge_dhcp_ip_route(iface_name);
                break;
            }
        }
    }
}

fn new_net_conf_with_ip_conf(iface_name: &str, ip_conf: IpConf) -> NetConf {
    let mut iface_conf = IfaceConf::default();
    iface_conf.name = iface_name.to_string();
    iface_conf.state = IfaceState::Up;
    iface_conf.ipv4 = Some(ip_conf);
    let mut net_conf = NetConf::default();
    net_conf.ifaces = Some(vec![iface_conf]);
    net_conf
}

fn apply_dhcp_ip_route(iface_name: &str, lease: &DhcpV4Lease) {
    let mut ip_addr_conf = IpAddrConf::default();
    ip_addr_conf.address = lease.yiaddr.to_string();
    ip_addr_conf.prefix_len = get_prefix_len(&lease.subnet_mask);
    ip_addr_conf.valid_lft = format!("{}sec", lease.lease_time);
    ip_addr_conf.preferred_lft = format!("{}sec", lease.lease_time);
    let mut ip_conf = IpConf::default();
    ip_conf.addresses = vec![ip_addr_conf];
    new_net_conf_with_ip_conf(iface_name, ip_conf)
        .apply()
        .unwrap();
}

fn get_prefix_len(ip: &std::net::Ipv4Addr) -> u8 {
    u32::from_be_bytes(ip.octets()).count_ones() as u8
}

// Remove all dynamic IP and dhcp routes of specified interface
fn purge_dhcp_ip_route(iface_name: &str) {
    let state = NetState::retrieve().unwrap();
    if let Some(ip_info) =
        state.ifaces.get(iface_name).and_then(|i| i.ipv4.as_ref())
    {
        let mut addrs_to_remove = Vec::new();
        for addr in ip_info
            .addresses
            .as_slice()
            .iter()
            .filter(|a| a.valid_lft != "forever")
        {
            let mut addr_conf = IpAddrConf::default();
            addr_conf.remove = true;
            addr_conf.address = addr.address.clone();
            addr_conf.prefix_len = addr.prefix_len;
            addrs_to_remove.push(addr_conf);
        }
        if !addrs_to_remove.is_empty() {
            let mut ip_conf = IpConf::default();
            ip_conf.addresses = addrs_to_remove;
            new_net_conf_with_ip_conf(iface_name, ip_conf)
                .apply()
                .unwrap();
        }
    }
}
