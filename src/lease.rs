use std::net::Ipv4Addr;

use dhcproto::{v4, v4::DhcpOption};

use crate::{time::BootTime, DhcpError};

#[derive(Debug, PartialEq, Clone)]
pub struct DhcpV4Lease {
    pub got_time: BootTime,
    pub siaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub t1: u32,
    pub t2: u32,
    pub lease_time: u32,
    pub srv_id: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub broadcast_addr: Option<Ipv4Addr>,
    pub dns_srvs: Option<Vec<Ipv4Addr>>,
    pub gateways: Option<Vec<Ipv4Addr>>,
    pub ntp_srvs: Option<Vec<Ipv4Addr>>,
    pub mtu: Option<u16>,
    pub host_name: Option<String>,
    pub domain_name: Option<String>,
    // TODO: We should save the unsupported DHCP options for external parser.
    //pub other_dhcp_opts: Vec<DhcpV4UnknownOption>,
}

impl Default for DhcpV4Lease {
    fn default() -> Self {
        Self {
            got_time: BootTime::new(0, 0),
            siaddr: Ipv4Addr::new(0, 0, 0, 0),
            yiaddr: Ipv4Addr::new(0, 0, 0, 0),
            t1: 0,
            t2: 0,
            lease_time: 0,
            srv_id: Ipv4Addr::new(0, 0, 0, 0),
            subnet_mask: Ipv4Addr::new(0, 0, 0, 0),
            broadcast_addr: None,
            dns_srvs: None,
            gateways: None,
            ntp_srvs: None,
            mtu: None,
            host_name: None,
            domain_name: None,
        }
    }
}

impl DhcpV4Lease {
    pub fn new() -> Self {
        Self::default()
    }
}

impl std::convert::TryFrom<&v4::Message> for DhcpV4Lease {
    type Error = DhcpError;
    fn try_from(v4_dhcp_msg: &v4::Message) -> Result<Self, Self::Error> {
        let mut ret = Self::new();
        ret.siaddr = v4_dhcp_msg.siaddr();
        ret.yiaddr = v4_dhcp_msg.yiaddr();
        ret.got_time = BootTime::now();
        for (_, dhcp_opt) in v4_dhcp_msg.opts().iter() {
            match dhcp_opt {
                DhcpOption::MessageType(_) => (),
                DhcpOption::Renewal(v) => {
                    ret.t1 = *v;
                }
                DhcpOption::Rebinding(v) => {
                    ret.t2 = *v;
                }
                DhcpOption::InterfaceMtu(v) => {
                    ret.mtu = Some(*v);
                }
                DhcpOption::ServerIdentifier(v) => {
                    ret.srv_id = *v;
                }
                DhcpOption::AddressLeaseTime(v) => {
                    ret.lease_time = *v;
                }
                DhcpOption::SubnetMask(v) => {
                    ret.subnet_mask = *v;
                }
                DhcpOption::BroadcastAddr(v) => {
                    ret.broadcast_addr = Some(*v);
                }
                DhcpOption::DomainNameServer(v) => {
                    ret.dns_srvs = Some(v.clone());
                }
                DhcpOption::Router(v) => {
                    ret.gateways = Some(v.clone());
                }
                DhcpOption::NTPServers(v) => {
                    ret.ntp_srvs = Some(v.clone());
                }
                DhcpOption::Hostname(v) => {
                    ret.host_name = Some(v.to_string());
                }
                DhcpOption::DomainName(v) => {
                    ret.domain_name = Some(v.to_string());
                }
                v => {
                    log::debug!("Unsupported DHCP opt {:?}", v);
                }
            }
        }
        // TODO: Validate T1 < T2 < lease_time.
        Ok(ret)
    }
}
