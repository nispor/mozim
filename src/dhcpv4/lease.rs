// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv4Addr;

use dhcproto::{v4, v4::DhcpOption, Encodable};

use super::option::{DhcpV4Options, V4_OPT_CODE_MS_CLASSLESS_STATIC_ROUTE};
use crate::{DhcpError, DhcpV4ClasslessRoute};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct DhcpV4Lease {
    // Required for sending DHCPRELEASE in proxy mode
    pub(crate) srv_mac: [u8; 6],
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
    pub classless_routes: Option<Vec<DhcpV4ClasslessRoute>>,
    dhcp_opts: DhcpV4Options,
}

impl Default for DhcpV4Lease {
    fn default() -> Self {
        Self {
            srv_mac: [u8::MAX; 6],
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
            classless_routes: None,
            dhcp_opts: DhcpV4Options::default(),
        }
    }
}

impl std::convert::TryFrom<&v4::Message> for DhcpV4Lease {
    type Error = DhcpError;
    fn try_from(v4_dhcp_msg: &v4::Message) -> Result<Self, Self::Error> {
        let mut ret = Self {
            siaddr: v4_dhcp_msg.siaddr(),
            yiaddr: v4_dhcp_msg.yiaddr(),
            dhcp_opts: DhcpV4Options::new(v4_dhcp_msg.opts().iter()),
            ..Default::default()
        };
        for (code, dhcp_opt) in v4_dhcp_msg.opts().iter() {
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
                DhcpOption::NtpServers(v) => {
                    ret.ntp_srvs = Some(v.clone());
                }
                DhcpOption::Hostname(v) => {
                    ret.host_name = Some(v.to_string());
                }
                DhcpOption::DomainName(v) => {
                    ret.domain_name = Some(v.to_string());
                }
                DhcpOption::ClasslessStaticRoute(v) => {
                    ret.classless_routes = Some(DhcpV4ClasslessRoute::parse(v));
                }
                DhcpOption::Unknown(v) => {
                    if *code
                        == v4::OptionCode::Unknown(
                            V4_OPT_CODE_MS_CLASSLESS_STATIC_ROUTE,
                        )
                        && ret.classless_routes.is_none()
                    {
                        if let Some(routes) = v
                            .to_vec()
                            .ok()
                            .and_then(DhcpV4ClasslessRoute::parse_raw)
                        {
                            ret.classless_routes = Some(routes);
                        }
                    }
                }
                _ => (),
            }
        }
        // TODO: Validate T1 < T2 < lease_time.
        Ok(ret)
    }
}

impl DhcpV4Lease {
    /// Return the raw data of specified DHCP option containing
    /// leading code and length(if available) also.
    pub fn get_option_raw(&self, code: u8) -> Option<&[u8]> {
        self.dhcp_opts.get_data_raw(code)
    }
}
