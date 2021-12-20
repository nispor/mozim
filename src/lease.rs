use std::net::Ipv4Addr;

use dhcproto::{v4, v4::DhcpOption};

use crate::DhcpError;

#[derive(Debug, PartialEq, Clone, Default)]
pub struct DhcpV4Lease {
    pub siaddr: Option<Ipv4Addr>,
    pub yiaddr: Option<Ipv4Addr>,
    pub t1_renew: u32,
    pub t2_rebinding: u32,
    pub lease_time: u32,
    pub srv_id: Option<Ipv4Addr>,
    pub subnet_mask: Option<String>,
    pub broadcast_addr: Option<String>,
    pub dns_srvs: Option<Vec<String>>,
    pub gateways: Option<Vec<String>>,
    pub ntp_srvs: Option<Vec<Ipv4Addr>>,
    pub mtu: Option<u16>,
    pub host_name: Option<String>,
    pub domain_name: Option<String>,
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
        ret.siaddr = Some(v4_dhcp_msg.siaddr());
        ret.yiaddr = Some(v4_dhcp_msg.yiaddr());
        for (_, dhcp_opt) in v4_dhcp_msg.opts().iter() {
            match dhcp_opt {
                DhcpOption::MessageType(_) => (),
                DhcpOption::Renewal(v) => {
                    ret.t1_renew = *v;
                }
                DhcpOption::Rebinding(v) => {
                    ret.t2_rebinding = *v;
                }
                DhcpOption::InterfaceMtu(v) => {
                    ret.mtu = Some(*v);
                }
                DhcpOption::ServerIdentifier(v) => {
                    ret.srv_id = Some(*v);
                }
                DhcpOption::AddressLeaseTime(v) => {
                    ret.lease_time = *v;
                }
                DhcpOption::SubnetMask(v) => {
                    ret.subnet_mask = Some(v.to_string());
                }
                DhcpOption::BroadcastAddr(v) => {
                    ret.broadcast_addr = Some(v.to_string());
                }
                DhcpOption::DomainNameServer(v) => {
                    ret.dns_srvs =
                        Some(v.iter().map(Ipv4Addr::to_string).collect());
                }
                DhcpOption::Router(v) => {
                    ret.gateways =
                        Some(v.iter().map(Ipv4Addr::to_string).collect());
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
        Ok(ret)
    }
}
