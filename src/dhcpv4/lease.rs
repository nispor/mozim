// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv4Addr;

use super::{
    msg::DhcpV4Message,
    option::{DhcpV4ClasslessRoutes, DhcpV4Options},
};
use crate::{
    DhcpError, DhcpV4ClasslessRoute, DhcpV4Option, DhcpV4OptionCode, ErrorKind,
};

#[derive(Debug, PartialEq, Clone)]
#[non_exhaustive]
pub struct DhcpV4Lease {
    // Required for sending DHCPRELEASE in proxy mode
    pub(crate) srv_mac: [u8; 6],
    /// Server IP address
    pub siaddr: Ipv4Addr,
    /// Your(Client) IP address
    pub yiaddr: Ipv4Addr,
    pub t1_sec: u32,
    pub t2_sec: u32,
    pub lease_time_sec: u32,
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
            t1_sec: 0,
            t2_sec: 0,
            lease_time_sec: 0,
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

impl DhcpV4Lease {
    pub(crate) fn new_from_msg(msg: &DhcpV4Message) -> Result<Self, DhcpError> {
        let mut ret = Self {
            siaddr: msg.siaddr,
            yiaddr: msg.yiaddr,
            dhcp_opts: msg.options.clone(),
            ..Default::default()
        };
        if let Some(DhcpV4Option::IpAddressLeaseTime(v)) =
            msg.options.get(DhcpV4OptionCode::IpAddressLeaseTime)
        {
            ret.lease_time_sec = *v;
        } else {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!("No lease time in DHCP message {msg:?}"),
            ));
        }

        if let Some(DhcpV4Option::RenewalTime(v)) =
            msg.options.get(DhcpV4OptionCode::RenewalTime)
        {
            ret.t1_sec = *v;
        } else {
            // RFC 2131 says we should pick 0.5 of the lease time if no t1
            // option given.
            ret.t1_sec = add_jitter(ret.lease_time_sec / 2);
        }

        if let Some(DhcpV4Option::RebindingTime(v)) =
            msg.options.get(DhcpV4OptionCode::RebindingTime)
        {
            ret.t2_sec = *v;
        } else {
            // RFC 2131 says we should pick 0.875 of the lease time if no t1
            // option given.
            ret.t2_sec = add_jitter((ret.lease_time_sec as f32 * 0.875) as u32);
        }

        if let Some(DhcpV4Option::InterfaceMtu(v)) =
            msg.options.get(DhcpV4OptionCode::InterfaceMtu)
        {
            ret.mtu = Some(*v);
        }
        if let Some(DhcpV4Option::ServerIdentifier(v)) =
            msg.options.get(DhcpV4OptionCode::ServerIdentifier)
        {
            ret.srv_id = *v;
        }
        if let Some(DhcpV4Option::SubnetMask(v)) =
            msg.options.get(DhcpV4OptionCode::SubnetMask)
        {
            ret.subnet_mask = *v;
        }
        if let Some(DhcpV4Option::BroadcastAddress(v)) =
            msg.options.get(DhcpV4OptionCode::BroadcastAddress)
        {
            ret.broadcast_addr = Some(*v);
        }
        if let Some(DhcpV4Option::DomainNameServer(v)) =
            msg.options.get(DhcpV4OptionCode::DomainNameServer)
        {
            ret.dns_srvs = Some(v.clone());
        }
        if let Some(DhcpV4Option::Router(v)) =
            msg.options.get(DhcpV4OptionCode::Router)
        {
            ret.gateways = Some(v.clone());
        }
        if let Some(DhcpV4Option::NtpServers(v)) =
            msg.options.get(DhcpV4OptionCode::NtpServers)
        {
            ret.ntp_srvs = Some(v.clone());
        }
        if let Some(DhcpV4Option::HostName(v)) =
            msg.options.get(DhcpV4OptionCode::HostName)
        {
            ret.host_name = Some(v.to_string());
        }
        if let Some(DhcpV4Option::DomainName(v)) =
            msg.options.get(DhcpV4OptionCode::DomainName)
        {
            ret.domain_name = Some(v.to_string());
        }
        if let Some(DhcpV4Option::ClasslessStaticRoute(v)) =
            msg.options.get(DhcpV4OptionCode::ClasslessStaticRoute)
        {
            ret.classless_routes = Some(v.clone());
        }

        if ret.classless_routes.is_none() {
            if let Some(raw) = msg.options.get_data_raw(
                DhcpV4OptionCode::MS_CLASSLESS_STATIC_ROUTE.into(),
            ) {
                if let Ok(v) = DhcpV4ClasslessRoutes::parse(raw.as_slice()) {
                    ret.classless_routes = Some(v);
                }
            }
        }
        ret.validate()?;
        Ok(ret)
    }

    fn validate(&self) -> Result<(), DhcpError> {
        if self.t1_sec > self.t2_sec {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                "Invalid DHCP lease: T1 is bigger than T2".to_string(),
            ));
        }
        if self.t2_sec > self.lease_time_sec {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                "Invalid DHCP lease: T2 is bigger than lease time".to_string(),
            ));
        }

        Ok(())
    }

    /// Return the raw data of specified DHCP option without
    /// leading code and length.
    pub fn get_option_raw(&self, code: u8) -> Option<Vec<u8>> {
        self.dhcp_opts.get_data_raw(code)
    }

    pub fn prefix_length(&self) -> u8 {
        u32::from(self.subnet_mask).count_ones() as u8
    }
}

/// Add a small random jitter of -2 to +2s to the value.
/// It will not add jitter for values below 20s to avoid
/// invalidating the t1 < t2 < lease time relationship.
fn add_jitter(val: u32) -> u32 {
    if val < 20 {
        return val;
    }
    val + rand::random_range(0..4) - 2
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_prefix_length() {
        assert_eq!(
            DhcpV4Lease {
                subnet_mask: Ipv4Addr::new(255, 255, 255, 224),
                ..Default::default()
            }
            .prefix_length(),
            27
        )
    }

    #[test]
    fn test_dhcp_v2_lease_t1_t2() {
        let mut opts = DhcpV4Options::new();
        opts.insert(DhcpV4Option::IpAddressLeaseTime(100));
        opts.insert(DhcpV4Option::RenewalTime(30));
        opts.insert(DhcpV4Option::RebindingTime(60));
        let msg = DhcpV4Message {
            options: opts.clone(),
            ..Default::default()
        };
        let lease = DhcpV4Lease::new_from_msg(&msg).unwrap();
        assert_eq!(
            lease,
            DhcpV4Lease {
                lease_time_sec: 100,
                t1_sec: 30,
                t2_sec: 60,
                dhcp_opts: opts,
                ..Default::default()
            }
        );
    }

    #[test]
    fn test_dhcp_v2_lease_default_t1_t2() {
        let mut opts = DhcpV4Options::new();
        opts.insert(DhcpV4Option::IpAddressLeaseTime(100));
        let msg = DhcpV4Message {
            options: opts,
            ..Default::default()
        };
        let lease = DhcpV4Lease::new_from_msg(&msg).unwrap();
        assert_eq!(lease.lease_time_sec, 100);
        // exact values are random due jitter so just check the range
        assert!(
            lease.t1_sec >= 48 && lease.t1_sec <= 52,
            "t1 seconds {} outside of range 48..52",
            lease.t1_sec
        );
        assert!(
            lease.t2_sec >= 85 && lease.t2_sec <= 89,
            "t2 seconds {} outside of range 85..89",
            lease.t2_sec
        );
    }
}
