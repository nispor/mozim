// SPDX-License-Identifier: Apache-2.0

use std::{net::Ipv6Addr, time::Duration};

use super::{msg::DhcpV6Message, option::DhcpV6Options};
use crate::{
    DhcpError, DhcpV6Duid, DhcpV6IaType, DhcpV6Option, DhcpV6OptionCode,
    DhcpV6OptionNtpServer, ErrorKind,
};

// Section 5 of RFC4941, one week
const TEMP_VALID_LIFETIME: Duration = Duration::from_secs(60u64 * 60 * 24 * 7);
// Section 5 of RFC4941, one day
const TEMP_PREFERRED_LIFETIME: Duration = Duration::from_secs(60u64 * 60 * 24);

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct DhcpV6Lease {
    pub t1_sec: u32,
    pub t2_sec: u32,
    pub preferred_time_sec: u32,
    pub valid_time_sec: u32,
    pub xid: u32,
    pub iaid: u32,
    pub ia_type: Option<DhcpV6IaType>,
    pub address: Ipv6Addr,
    // Only valid for IA_PD(Prefix Delegation)
    pub prefix_len: u8,
    pub cli_duid: DhcpV6Duid,
    pub srv_duid: DhcpV6Duid,
    pub srv_ip: Ipv6Addr,
    /// NTP servers from OPTION_NTP_SERVER (RFC 5908). Addresses are
    /// strings; FQDNs are kept as received.
    pub ntp_srvs: Vec<String>,
    /// Domain search list from OPTION_DOMAIN_LIST (RFC 3646).
    pub domain_list: Vec<String>,
    /// DNS recursive name servers from OPTION_DNS_SERVERS (RFC 3646)
    /// in server preference order.
    pub dns_srvs: Vec<Ipv6Addr>,
    dhcp_opts: DhcpV6Options,
}

impl Default for DhcpV6Lease {
    fn default() -> Self {
        Self {
            t1_sec: 0,
            t2_sec: 0,
            preferred_time_sec: 0,
            valid_time_sec: 0,
            xid: 0,
            iaid: 0,
            ia_type: None,
            address: Ipv6Addr::UNSPECIFIED,
            prefix_len: 128,
            cli_duid: DhcpV6Duid::default(),
            srv_duid: DhcpV6Duid::default(),
            dhcp_opts: DhcpV6Options::default(),
            srv_ip: Ipv6Addr::UNSPECIFIED,
            ntp_srvs: Vec::new(),
            domain_list: Vec::new(),
            dns_srvs: Vec::new(),
        }
    }
}

impl DhcpV6Lease {
    /// Return the raw data of specified DHCP option without
    /// leading code and length(if available).
    /// Since DHCPv6 allows multiple DHCP option for each code,
    /// the return data is array of u8 array.
    pub fn get_option_raw(&self, code: u16) -> Option<Vec<Vec<u8>>> {
        self.dhcp_opts.get_data_raw(code)
    }

    pub(crate) fn new_from_msg(
        msg: &DhcpV6Message,
        expected_cli_duid: &DhcpV6Duid,
    ) -> Result<Self, DhcpError> {
        let mut ret = Self {
            xid: msg.xid(),
            dhcp_opts: msg.options.clone(),
            ..Default::default()
        };
        // RFC 8415 sections 16.3 and 16.10: a client must discard an
        // Advertise/Reply that lacks a Server Identifier, lacks a Client
        // Identifier, or carries a Client Identifier that does not match the
        // client's DUID.
        if let Some(DhcpV6Option::ServerId(v)) =
            msg.options.get_first(DhcpV6OptionCode::ServerId)
        {
            ret.srv_duid = v.clone();
        } else {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                "DHCPv6 reply contains no Server Identifier".to_string(),
            ));
        }
        match msg.options.get_first(DhcpV6OptionCode::ClientId) {
            Some(DhcpV6Option::ClientId(v)) if v == expected_cli_duid => {
                ret.cli_duid = v.clone();
            }
            _ => {
                return Err(DhcpError::new(
                    ErrorKind::InvalidDhcpMessage,
                    "DHCPv6 reply Client Identifier missing or not matching \
                     this client's DUID"
                        .to_string(),
                ));
            }
        }
        if let Some(DhcpV6Option::IANA(v)) =
            msg.options.get_first(DhcpV6OptionCode::IANA)
        {
            ret.ia_type = Some(DhcpV6IaType::NonTemporaryAddresses);
            // RFC 8415: In a typical deployment, the server will grant
            // one address for each IA_NA option.
            // So we only take first address
            if v.is_success() {
                if let Some(addr) = v.address.as_ref() {
                    ret.address = addr.address;
                    ret.preferred_time_sec = addr.preferred_time_sec;
                    ret.valid_time_sec = addr.valid_time_sec;
                    ret.iaid = v.iaid;
                    ret.t1_sec = v.t1_sec;
                    ret.t2_sec = v.t2_sec;
                }
            } else if let Some(status) = v.status.as_ref() {
                log::info!(
                    "Lease not successful for IANA in DHCPv6 message: code \
                     {}, message {}",
                    status.status,
                    status.message
                );
            } else if let Some(status) =
                v.address.as_ref().and_then(|addr| addr.status.as_ref())
            {
                log::info!(
                    "Lease not successful for IANA in DHCPv6 message: code \
                     {}, message {}",
                    status.status,
                    status.message
                );
            }
        }
        if let Some(DhcpV6Option::IATA(v)) =
            msg.options.get_first(DhcpV6OptionCode::IATA)
        {
            ret.ia_type = Some(DhcpV6IaType::TemporaryAddresses);

            if v.is_success() {
                if let Some(addr) = v.address.as_ref() {
                    ret.address = addr.address;
                    ret.preferred_time_sec =
                        TEMP_PREFERRED_LIFETIME.as_secs() as u32;
                    ret.valid_time_sec = TEMP_VALID_LIFETIME.as_secs() as u32;
                    ret.iaid = v.iaid;
                }
            } else if let Some(status) = v.status.as_ref() {
                log::info!(
                    "Lease not successful for IATA in DHCPv6 message: code \
                     {}, message {}",
                    status.status,
                    status.message
                );
            } else if let Some(status) =
                v.address.as_ref().and_then(|addr| addr.status.as_ref())
            {
                log::info!(
                    "Lease not successful for IATA in DHCPv6 message: code \
                     {}, message {}",
                    status.status,
                    status.message
                );
            }
        }
        if let Some(DhcpV6Option::IAPD(v)) =
            msg.options.get_first(DhcpV6OptionCode::IAPD)
        {
            ret.ia_type = Some(DhcpV6IaType::PrefixDelegation);
            if v.is_success() {
                if let Some(prefix) = v.prefix.as_ref() {
                    ret.address = prefix.prefix;
                    ret.preferred_time_sec = prefix.preferred_time_sec;
                    ret.valid_time_sec = prefix.valid_time_sec;
                    ret.prefix_len = prefix.prefix_len;
                    ret.iaid = v.iaid;
                    ret.t1_sec = v.t1_sec;
                    ret.t2_sec = v.t2_sec;
                }
            } else if let Some(status) = v.status.as_ref() {
                log::info!(
                    "Lease not successful for IAPD in DHCPv6 message: code \
                     {}, message {}",
                    status.status,
                    status.message
                );
            } else if let Some(status) =
                v.prefix.as_ref().and_then(|prefix| prefix.status.as_ref())
            {
                log::info!(
                    "Lease not successful for IAPD in DHCPv6 message: code \
                     {}, message {}",
                    status.status,
                    status.message
                );
            }
        }
        if let Some(DhcpV6Option::ServerUnicast(srv_ip)) =
            msg.options.get_first(DhcpV6OptionCode::ServerUnicast)
        {
            ret.srv_ip = *srv_ip;
        }
        if let Some(DhcpV6Option::NtpServer(srvs)) =
            msg.options.get_first(DhcpV6OptionCode::NtpServer)
        {
            ret.ntp_srvs = srvs
                .iter()
                .filter_map(|srv| match srv {
                    DhcpV6OptionNtpServer::ServerAddr(ip) => {
                        Some(ip.to_string())
                    }
                    DhcpV6OptionNtpServer::MulticastAddr(ip) => {
                        Some(ip.to_string())
                    }
                    DhcpV6OptionNtpServer::ServerFqdn(fqdn) => {
                        Some(fqdn.clone())
                    }
                    DhcpV6OptionNtpServer::Other(..) => None,
                })
                .collect();
        }
        if let Some(DhcpV6Option::DomainList(domains)) =
            msg.options.get_first(DhcpV6OptionCode::DomainList)
        {
            ret.domain_list = domains.clone();
        }
        if let Some(DhcpV6Option::DnsServers(srvs)) =
            msg.options.get_first(DhcpV6OptionCode::DnsServers)
        {
            ret.dns_srvs = srvs.clone();
        }
        if let Some(DhcpV6Option::StatusCode(v)) =
            msg.options.get_first(DhcpV6OptionCode::StatusCode)
        {
            if !v.is_success() {
                return Err(DhcpError::new(
                    ErrorKind::NoLease,
                    format!(
                        "DHCP server reply status code {}, message {}",
                        v.status, v.message
                    ),
                ));
            }
        }
        ret.sanitize_lease()?;
        log::debug!("Found DHCP lease {} from DHCP message", ret.address);
        Ok(ret)
    }

    pub(crate) fn sanitize_lease(&mut self) -> Result<(), DhcpError> {
        // RFC 8415 14.2. Client Behavior when T1 and/or T2 Are 0.
        // Zero means the renew and rebind times are left to the
        // discretion of the client, so pick a non-zero default to
        // avoid renewing immediately.
        if self.t1_sec == 0 && self.preferred_time_sec != 0 {
            self.t1_sec = self.preferred_time_sec / 2;
        }
        if self.t2_sec == 0 && self.preferred_time_sec != 0 {
            self.t2_sec =
                self.preferred_time_sec / 2 + self.preferred_time_sec / 4;
        }
        if self.t1_sec == 0 {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                "DHCPv6 lease contains zero T1".to_string(),
            ));
        }
        if self.t2_sec == 0 {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                "DHCPv6 lease contains zero T2".to_string(),
            ));
        }
        if self.t1_sec > self.t2_sec {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!(
                    "DHCPv6 lease contains T1({} secs) bigger than T2 ({} \
                     secs)",
                    self.t1_sec, self.t2_sec
                ),
            ));
        }

        if self.t2_sec > self.valid_time_sec {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!(
                    "DHCPv6 lease contains T2({} secs) bigger than valid ({} \
                     secs)",
                    self.t2_sec, self.valid_time_sec
                ),
            ));
        }

        if self.preferred_time_sec > self.valid_time_sec {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!(
                    "DHCPv6 lease contains preferred ({} secs) bigger than \
                     valid ({} secs)",
                    self.preferred_time_sec, self.valid_time_sec
                ),
            ));
        }

        if self.srv_duid.is_empty() {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                "DHCPv6 lease contains empty server DUID".to_string(),
            ));
        }
        if self.address == Ipv6Addr::UNSPECIFIED {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                "DHCPv6 lease contains invalid all zero lease IPv6 address"
                    .to_string(),
            ));
        }
        // RFC 8415 section 21.22: the "prefix-length" field of an
        // OPTION_IAPREFIX is the length of an IPv6 prefix in bits, hence
        // cannot exceed 128.
        if self.prefix_len > 128 {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!(
                    "DHCPv6 lease contains invalid prefix length {}, should \
                     be 0 - 128",
                    self.prefix_len
                ),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv6Addr;

    use super::*;
    use crate::{
        dhcpv6::msg::DhcpV6MessageType, DhcpV6OptionIaAddr, DhcpV6OptionIaNa,
        DhcpV6OptionIaPd, DhcpV6OptionIaPrefix,
    };

    fn prefix_delegation_reply(
        client_duid: &DhcpV6Duid,
        prefix_len: u8,
    ) -> DhcpV6Message {
        let mut msg = DhcpV6Message {
            msg_type: DhcpV6MessageType::Reply,
            ..Default::default()
        };
        msg.options
            .insert(DhcpV6Option::ClientId(client_duid.clone()));
        msg.options
            .insert(DhcpV6Option::ServerId(DhcpV6Duid::Raw(vec![2])));
        msg.options.insert(DhcpV6Option::IAPD(DhcpV6OptionIaPd::new(
            1,
            60,
            90,
            DhcpV6OptionIaPrefix::new(
                Ipv6Addr::new(0x2001, 0x0db8, 0x000a, 0, 0, 0, 0, 0),
                prefix_len,
                120,
                240,
            ),
        )));
        msg
    }

    #[test]
    fn prefix_delegation_rejects_prefix_len_over_128() {
        let client_duid = DhcpV6Duid::Raw(vec![1]);
        let msg = prefix_delegation_reply(&client_duid, 129);

        let err = DhcpV6Lease::new_from_msg(&msg, &client_duid).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidDhcpMessage);
        assert!(
            err.msg().contains("prefix length"),
            "unexpected error message: {}",
            err.msg()
        );
    }

    #[test]
    fn prefix_delegation_accepts_prefix_len_128() {
        let client_duid = DhcpV6Duid::Raw(vec![1]);
        let msg = prefix_delegation_reply(&client_duid, 128);

        let lease = DhcpV6Lease::new_from_msg(&msg, &client_duid).unwrap();

        assert_eq!(lease.prefix_len, 128);
    }

    #[test]
    fn sanitize_lease_accepts_unspecified_prefix_len_hint() {
        let mut lease = DhcpV6Lease {
            t1_sec: 60,
            t2_sec: 90,
            preferred_time_sec: 120,
            valid_time_sec: 240,
            address: Ipv6Addr::new(0x2001, 0x0db8, 0x000a, 0, 0, 0, 0, 0),
            srv_duid: DhcpV6Duid::Raw(vec![2]),
            prefix_len: 0,
            ..Default::default()
        };

        lease.sanitize_lease().unwrap();

        assert_eq!(lease.prefix_len, 0);
    }

    #[test]
    fn lease_reads_ntp_fqdn_and_domain_list() {
        let client_duid = DhcpV6Duid::Raw(vec![1]);
        let mut msg = DhcpV6Message {
            msg_type: DhcpV6MessageType::Advertise,
            ..Default::default()
        };
        msg.options
            .insert(DhcpV6Option::ClientId(client_duid.clone()));
        msg.options
            .insert(DhcpV6Option::ServerId(DhcpV6Duid::Raw(vec![2])));
        msg.options.insert(DhcpV6Option::DomainList(vec![
            "example.com".to_string(),
            "example.org".to_string(),
        ]));
        msg.options.insert(DhcpV6Option::NtpServer(vec![
            DhcpV6OptionNtpServer::ServerFqdn("ntp.example.com".to_string()),
            DhcpV6OptionNtpServer::ServerFqdn("ntp2.example.com".to_string()),
        ]));
        msg.options.insert(DhcpV6Option::IANA(DhcpV6OptionIaNa::new(
            1,
            60,
            90,
            DhcpV6OptionIaAddr::new(
                Ipv6Addr::new(0x2001, 0x0db8, 0x000a, 0, 0, 0, 0, 0x99),
                120,
                240,
            ),
        )));

        let lease = DhcpV6Lease::new_from_msg(&msg, &client_duid).unwrap();
        assert_eq!(lease.cli_duid, client_duid);
        assert_eq!(
            lease.domain_list,
            vec!["example.com".to_string(), "example.org".to_string()]
        );
        assert_eq!(
            lease.ntp_srvs,
            vec![
                "ntp.example.com".to_string(),
                "ntp2.example.com".to_string(),
            ]
        );
    }

    #[test]
    fn lease_reads_dns_servers() {
        let client_duid = DhcpV6Duid::Raw(vec![1]);
        let mut msg = DhcpV6Message {
            msg_type: DhcpV6MessageType::Advertise,
            ..Default::default()
        };
        msg.options
            .insert(DhcpV6Option::ClientId(client_duid.clone()));
        msg.options
            .insert(DhcpV6Option::ServerId(DhcpV6Duid::Raw(vec![2])));
        msg.options.insert(DhcpV6Option::DnsServers(vec![
            Ipv6Addr::new(0x2001, 0x0db8, 0x000a, 0, 0, 0, 0, 0x53),
            Ipv6Addr::new(0x2001, 0x0db8, 0x000a, 0, 0, 0, 0, 0x54),
        ]));
        msg.options.insert(DhcpV6Option::IANA(DhcpV6OptionIaNa::new(
            1,
            60,
            90,
            DhcpV6OptionIaAddr::new(
                Ipv6Addr::new(0x2001, 0x0db8, 0x000a, 0, 0, 0, 0, 0x99),
                120,
                240,
            ),
        )));

        let lease = DhcpV6Lease::new_from_msg(&msg, &client_duid).unwrap();
        assert_eq!(
            lease.dns_srvs,
            vec![
                Ipv6Addr::new(0x2001, 0x0db8, 0x000a, 0, 0, 0, 0, 0x53),
                Ipv6Addr::new(0x2001, 0x0db8, 0x000a, 0, 0, 0, 0, 0x54),
            ]
        );
    }

    fn valid_reply_msg(client_duid: &DhcpV6Duid) -> DhcpV6Message {
        let mut msg = DhcpV6Message {
            msg_type: DhcpV6MessageType::Reply,
            ..Default::default()
        };
        msg.options
            .insert(DhcpV6Option::ClientId(client_duid.clone()));
        msg.options
            .insert(DhcpV6Option::ServerId(DhcpV6Duid::Raw(vec![2])));
        msg.options.insert(DhcpV6Option::IANA(DhcpV6OptionIaNa::new(
            1,
            60,
            90,
            DhcpV6OptionIaAddr::new(
                Ipv6Addr::new(0x2001, 0x0db8, 0x000a, 0, 0, 0, 0, 0x99),
                120,
                240,
            ),
        )));
        msg
    }

    #[test]
    fn new_from_msg_accepts_matching_reply_identifiers() {
        let client_duid = DhcpV6Duid::Raw(vec![1]);
        let msg = valid_reply_msg(&client_duid);

        let lease = DhcpV6Lease::new_from_msg(&msg, &client_duid).unwrap();

        assert_eq!(lease.cli_duid, client_duid);
        assert_eq!(lease.srv_duid, DhcpV6Duid::Raw(vec![2]));
    }

    #[test]
    fn new_from_msg_rejects_reply_without_server_identifier() {
        let client_duid = DhcpV6Duid::Raw(vec![1]);
        let mut msg = valid_reply_msg(&client_duid);
        msg.options.remove(DhcpV6OptionCode::ServerId);

        let err = DhcpV6Lease::new_from_msg(&msg, &client_duid).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidDhcpMessage);
        assert!(
            err.msg().contains("Server Identifier"),
            "unexpected error message: {}",
            err.msg()
        );
    }

    #[test]
    fn new_from_msg_rejects_reply_without_client_identifier() {
        let client_duid = DhcpV6Duid::Raw(vec![1]);
        let mut msg = valid_reply_msg(&client_duid);
        msg.options.remove(DhcpV6OptionCode::ClientId);

        let err = DhcpV6Lease::new_from_msg(&msg, &client_duid).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidDhcpMessage);
        assert!(
            err.msg().contains("Client Identifier"),
            "unexpected error message: {}",
            err.msg()
        );
    }

    #[test]
    fn new_from_msg_rejects_mismatched_client_identifier() {
        let client_duid = DhcpV6Duid::Raw(vec![1]);
        let mut msg = valid_reply_msg(&client_duid);
        msg.options.remove(DhcpV6OptionCode::ClientId);
        msg.options
            .insert(DhcpV6Option::ClientId(DhcpV6Duid::Raw(vec![2])));

        let err = DhcpV6Lease::new_from_msg(&msg, &client_duid).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidDhcpMessage);
        assert!(
            err.msg().contains("Client Identifier"),
            "unexpected error message: {}",
            err.msg()
        );
    }
}
