// SPDX-License-Identifier: Apache-2.0

use std::{net::Ipv6Addr, time::Duration};

use super::{msg::DhcpV6Message, option::DhcpV6Options};
use crate::{
    DhcpError, DhcpV6Duid, DhcpV6IaType, DhcpV6Option, DhcpV6OptionCode,
    ErrorKind,
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
    pub ntp_srvs: Vec<String>,
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

    pub(crate) fn new_from_msg(msg: &DhcpV6Message) -> Result<Self, DhcpError> {
        let mut ret = Self {
            xid: msg.xid(),
            dhcp_opts: msg.options.clone(),
            ..Default::default()
        };
        if let Some(DhcpV6Option::ClientId(v)) =
            msg.options.get_first(DhcpV6OptionCode::ClientId)
        {
            ret.cli_duid = v.clone();
        }
        if let Some(DhcpV6Option::ServerId(v)) =
            msg.options.get_first(DhcpV6OptionCode::ServerId)
        {
            ret.srv_duid = v.clone();
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
                    // RFC 8415 14.2. Client Behavior when T1 and/or T2 Are 0
                    // This is an indication that the renew and rebind times are
                    // left to the discretion of the client.
                    if ret.t1_sec == 0 && ret.preferred_time_sec != 0 {
                        ret.t1_sec = ret.preferred_time_sec / 2;
                    }
                    if ret.t2_sec == 0 && ret.preferred_time_sec != 0 {
                        ret.t2_sec = ret.preferred_time_sec / 2
                            + ret.preferred_time_sec / 4;
                    }
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
                    // RFC 8415 14.2. Client Behavior when T1 and/or T2 Are 0
                    // This is an indication that the renew and rebind times are
                    // left to the discretion of the client.
                    if ret.t1_sec == 0 && ret.preferred_time_sec != 0 {
                        ret.t1_sec = ret.preferred_time_sec / 2;
                    }
                    if ret.t2_sec == 0 && ret.preferred_time_sec != 0 {
                        ret.t2_sec = ret.preferred_time_sec / 2
                            + ret.preferred_time_sec / 4;
                    }
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

    fn sanitize_lease(&self) -> Result<(), DhcpError> {
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
        Ok(())
    }
}
