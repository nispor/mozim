// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv6Addr;

use dhcproto::{
    v6,
    v6::{DhcpOption, DhcpOptions},
};

use crate::{DhcpError, DhcpV6IaType, ErrorKind};

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct DhcpV6Lease {
    pub t1: u32,
    pub t2: u32,
    pub xid: [u8; 3],
    pub iaid: u32,
    pub ia_type: DhcpV6IaType,
    pub addr: Ipv6Addr,
    pub prefix_len: u8,
    // TODO: OPTION_UNICAST
    //      For Request, Renew, Information-request, Release, and Decline
    //      messages, it is allowed only if the Server Unicast option is
    //      configured.
    pub preferred_life: u32,
    pub valid_life: u32,
    pub cli_duid: Vec<u8>,
    pub srv_duid: Vec<u8>,
    pub dhcp_opts: Vec<dhcproto::v6::DhcpOption>,
    pub srv_ip: Ipv6Addr,
}

impl Default for DhcpV6Lease {
    fn default() -> Self {
        Self {
            t1: 0,
            t2: 0,
            xid: [0; 3],
            iaid: 0,
            ia_type: DhcpV6IaType::TemporaryAddresses,
            addr: Ipv6Addr::UNSPECIFIED,
            prefix_len: 128,
            preferred_life: 0,
            valid_life: 0,
            cli_duid: Vec::new(),
            srv_duid: Vec::new(),
            dhcp_opts: Vec::new(),
            srv_ip: Ipv6Addr::UNSPECIFIED,
        }
    }
}

impl std::convert::TryFrom<&v6::Message> for DhcpV6Lease {
    type Error = DhcpError;
    fn try_from(v6_dhcp_msg: &v6::Message) -> Result<Self, Self::Error> {
        let mut ret = Self {
            xid: v6_dhcp_msg.xid(),
            ..Default::default()
        };
        for dhcp_opt in v6_dhcp_msg.opts().iter() {
            match dhcp_opt {
                DhcpOption::ClientId(v) => ret.cli_duid = v.clone(),
                DhcpOption::ServerId(v) => ret.srv_duid = v.clone(),
                DhcpOption::IANA(v) => {
                    ret.ia_type = DhcpV6IaType::NonTemporaryAddresses;
                    ret.iaid = v.id;
                    ret.t1 = v.t1;
                    ret.t2 = v.t2;
                    parse_dhcp_opt_iaadr(&v.opts, &mut ret);
                }
                DhcpOption::IATA(v) => {
                    ret.ia_type = DhcpV6IaType::TemporaryAddresses;
                    ret.iaid = v.id;
                    parse_dhcp_opt_iaadr(&v.opts, &mut ret);
                }
                DhcpOption::IAPD(v) => {
                    ret.ia_type = DhcpV6IaType::PrefixDelegation;
                    ret.iaid = v.id;
                    ret.t1 = v.t1;
                    ret.t2 = v.t2;
                    parse_dhcp_opt_iaadr(&v.opts, &mut ret);
                }
                DhcpOption::ServerUnicast(srv_ip) => {
                    ret.srv_ip = *srv_ip;
                }
                DhcpOption::StatusCode(v) => {
                    if v.status != v6::Status::Success {
                        return Err(DhcpError::new(
                            ErrorKind::NoLease,
                            format!(
                                "DHCP server reply status code {}({:?}), \
                                message {}",
                                u16::from(v.status),
                                v.status,
                                v.msg
                            ),
                        ));
                    }
                }
                v => {
                    log::debug!("Unsupported DHCPv6 opt {:?}", v);
                }
            }
        }
        ret.dhcp_opts = v6_dhcp_msg.opts().iter().cloned().collect();
        // TODO: Validate T1 < T2 < lease_time.
        Ok(ret)
    }
}

fn parse_dhcp_opt_iaadr(opts: &DhcpOptions, lease: &mut DhcpV6Lease) {
    if let Some(DhcpOption::IAPrefix(a)) = opts.get(v6::OptionCode::IAPrefix) {
        lease.addr = a.prefix_ip;
        lease.prefix_len = a.prefix_len;
        lease.preferred_life = a.preferred_lifetime;
        lease.valid_life = a.valid_lifetime;
    }
    if let Some(DhcpOption::IAAddr(a)) = opts.get(v6::OptionCode::IAAddr) {
        lease.addr = a.addr;
        lease.preferred_life = a.preferred_life;
        lease.valid_life = a.valid_life;
        lease.prefix_len = 128
    }
}
