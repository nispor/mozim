// SPDX-License-Identifier: Apache-2.0

use mozim::{DhcpV4Client, DhcpV4Config, DhcpV4Lease};
use nispor::{
    AddressFamily, IfaceConf, IfaceState, IpAddrConf, IpConf, NetConf,
    NetState, NetStateFilter, NetStateIfaceFilter, NetStateRouteFilter,
    RouteConf, RouteProtocol,
};

const DEFAULT_METRIC: u32 = 500;
const POLL_WAIT_TIME: isize = 5;
const APP_NAME: &str = "mzc";

const SUBCOMMAND_RUN: &str = "run";
const SUBCOMMAND_PROXY: &str = "proxy";
const SUBCOMMAND_CLEAN: &str = "clean";
const SUBCOMMAND_VERSION: &str = "version";
const ARG_IFNAME: &str = "ifname";
const ARG_TIMEOUT: &str = "timeout";
const ARG_MAC: &str = "mac";
const DEFAULT_TIMEOUT_STR: &str = "480";

fn main() {
    env_logger::Builder::new()
        .filter(Some("nispor"), log::LevelFilter::Debug)
        .filter(Some("mozim"), log::LevelFilter::Debug)
        .filter(Some("mzc"), log::LevelFilter::Debug)
        .init();

    let matches = clap::Command::new(APP_NAME)
        .version(clap::crate_version!())
        .author("Gris Ge <fge@redhat.com>")
        .about("Command line of mozim")
        .subcommand_required(true)
        .subcommand(
            clap::Command::new(SUBCOMMAND_RUN)
                .alias("r")
                .about("Run DHCP Client")
                .arg(
                    clap::Arg::new(ARG_IFNAME)
                        .index(1)
                        .help("Interface name")
                        .takes_value(true),
                )
                .arg(
                    clap::Arg::new(ARG_TIMEOUT)
                        .help("Timeout, default to 480 seconds")
                        .long(ARG_TIMEOUT)
                        .short('t')
                        .takes_value(true)
                        .default_value(DEFAULT_TIMEOUT_STR),
                ),
        )
        .subcommand(
            clap::Command::new(SUBCOMMAND_PROXY)
                .alias("p")
                .about("Run DHCP Client proxy")
                .arg(
                    clap::Arg::new(ARG_IFNAME)
                        .index(1)
                        .help("Outgoing interface name")
                        .takes_value(true),
                )
                .arg(
                    clap::Arg::new(ARG_MAC)
                        .index(2)
                        .help("MAC address to proxy")
                        .takes_value(true),
                )
                .arg(
                    clap::Arg::new(ARG_TIMEOUT)
                        .help("Timeout, default to 480 seconds")
                        .long(ARG_TIMEOUT)
                        .short('t')
                        .takes_value(true)
                        .default_value(DEFAULT_TIMEOUT_STR),
                ),
        )
        .subcommand(
            clap::Command::new(SUBCOMMAND_CLEAN)
                .alias("c")
                .about("Clean up DHCP IP and routes on specified interface")
                .arg(
                    clap::Arg::new(ARG_IFNAME)
                        .index(1)
                        .help("Interface name")
                        .takes_value(true),
                ),
        )
        .subcommand(
            clap::Command::new(SUBCOMMAND_VERSION)
                .alias("v")
                .about("Show version"),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches(SUBCOMMAND_RUN) {
        let timeout = matches
            .value_of(ARG_TIMEOUT)
            .unwrap_or(DEFAULT_TIMEOUT_STR)
            .parse::<u32>()
            .unwrap();
        if let Some(iface_name) = matches.value_of(ARG_IFNAME) {
            run(iface_name, timeout)
        }
    } else if let Some(matches) = matches.subcommand_matches(SUBCOMMAND_PROXY) {
        let timeout = matches
            .value_of(ARG_TIMEOUT)
            .unwrap_or(DEFAULT_TIMEOUT_STR)
            .parse::<u32>()
            .unwrap();
        if let Some(iface_name) = matches.value_of(ARG_IFNAME) {
            proxy(iface_name, matches.value_of(ARG_MAC).unwrap(), timeout)
        }
    } else if let Some(matches) = matches.subcommand_matches(SUBCOMMAND_CLEAN) {
        if let Some(iface_name) = matches.value_of(ARG_IFNAME) {
            purge_dhcp_ip_route(iface_name);
        }
    } else if matches.subcommand_matches(SUBCOMMAND_VERSION).is_some() {
        println!("{} {}", APP_NAME, clap::crate_version!());
    }
}

fn run(iface_name: &str, timeout: u32) {
    purge_dhcp_ip_route(iface_name);

    let mut config = DhcpV4Config::new(iface_name).unwrap();
    config.set_host_name("Gris-Laptop");
    config.use_host_name_as_client_id();
    config.set_timeout(timeout);
    let mut cli = DhcpV4Client::init(config, None).unwrap();

    loop {
        match cli.poll(POLL_WAIT_TIME) {
            Ok(events) => {
                for event in events {
                    match cli.process(event) {
                        Ok(Some(lease)) => {
                            apply_dhcp_ip_route(iface_name, &lease);
                        }
                        Ok(None) => (),
                        Err(_) => {
                            purge_dhcp_ip_route(iface_name);
                            return;
                        }
                    }
                }
            }
            Err(_) => {
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
    let mut net_conf = new_net_conf_with_ip_conf(iface_name, ip_conf);
    if let Some(gws) = lease.gateways.as_ref() {
        let mut routes = Vec::new();
        for (i, gw) in gws.as_slice().iter().enumerate() {
            routes.push(gen_rt_conf(
                false,
                "0.0.0.0/0",
                iface_name,
                &gw.to_string(),
                Some(DEFAULT_METRIC + i as u32),
            ));
        }
        if !routes.is_empty() {
            net_conf.routes = Some(routes);
        }
    }

    log::debug!("Applying {:?}", net_conf);
    net_conf.apply().unwrap();
}

fn get_prefix_len(ip: &std::net::Ipv4Addr) -> u8 {
    u32::from_be_bytes(ip.octets()).count_ones() as u8
}

// Remove all dynamic IP and dhcp routes of specified interface
fn purge_dhcp_ip_route(iface_name: &str) {
    let mut iface_filter = NetStateIfaceFilter::minimum();
    iface_filter.iface_name = Some(iface_name.to_string());
    iface_filter.include_ip_address = true;
    let mut route_filter = NetStateRouteFilter::default();
    route_filter.protocol = Some(RouteProtocol::Dhcp);

    let mut filter = NetStateFilter::minimum();
    filter.iface = Some(iface_filter);
    filter.route = Some(route_filter);

    let state = NetState::retrieve_with_filter(&filter).unwrap();
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
    let mut routes_to_remove = Vec::new();
    for rt in state.routes.as_slice().iter().filter(|rt| {
        rt.oif.as_deref() == Some(iface_name)
            && rt.protocol == RouteProtocol::Dhcp
            && rt.address_family == AddressFamily::IPv4
    }) {
        routes_to_remove.push(gen_rt_conf(
            true,
            rt.dst.as_deref().unwrap_or("0.0.0.0/0"),
            iface_name,
            rt.via
                .as_deref()
                .unwrap_or_else(|| rt.gateway.as_deref().unwrap_or("0.0.0.0")),
            None,
        ));
    }
    let mut net_conf = NetConf::default();
    net_conf.routes = Some(routes_to_remove);
    net_conf.apply().unwrap();
}

fn gen_rt_conf(
    remove: bool,
    dst: &str,
    oif: &str,
    via: &str,
    metric: Option<u32>,
) -> RouteConf {
    let mut rt = RouteConf::default();
    rt.remove = remove;
    rt.dst = dst.to_string();
    rt.oif = Some(oif.to_string());
    rt.via = Some(via.to_string());
    rt.table = Some(254);
    rt.metric = metric;
    rt.protocol = Some(RouteProtocol::Dhcp);
    rt
}

fn proxy(iface_name: &str, mac: &str, timeout: u32) {
    let mut config = DhcpV4Config::new_proxy(iface_name, mac).unwrap();
    config.set_timeout(timeout);
    let mut cli = DhcpV4Client::init(config, None).unwrap();

    loop {
        match cli.poll(POLL_WAIT_TIME) {
            Ok(events) => {
                for event in events {
                    match cli.process(event) {
                        Ok(Some(lease)) => {
                            println!("{:?}", lease);
                        }
                        Ok(None) => (),
                        Err(e) => {
                            eprintln!("Error {:?}", e);
                            return;
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Error {:?}", e);
                break;
            }
        }
    }
}
