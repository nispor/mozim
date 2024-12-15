// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv6Addr;
use std::time::Instant;

use dhcproto::{
    v6,
    v6::{DhcpOption, DhcpOptions},
    Decodable, Decoder, Encodable,
};

use crate::{DhcpError, DhcpV6Config, DhcpV6IaType, DhcpV6Lease, ErrorKind};

const DEFAULT_IAID: u32 = 0;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct DhcpV6MessageType(v6::MessageType);

impl DhcpV6MessageType {
    pub(crate) const SOLICIT: Self =
        DhcpV6MessageType(v6::MessageType::Solicit);

    pub(crate) const ADVERTISE: Self =
        DhcpV6MessageType(v6::MessageType::Advertise);

    pub(crate) const REQUEST: Self =
        DhcpV6MessageType(v6::MessageType::Request);

    pub(crate) const REPLY: Self = DhcpV6MessageType(v6::MessageType::Reply);
    pub(crate) const RENEW: Self = DhcpV6MessageType(v6::MessageType::Renew);
    pub(crate) const REBIND: Self = DhcpV6MessageType(v6::MessageType::Rebind);
}

impl Default for DhcpV6MessageType {
    fn default() -> Self {
        Self(v6::MessageType::Unknown(0))
    }
}

impl std::fmt::Display for DhcpV6MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}",
            match self.0 {
                v6::MessageType::Solicit => "solicit",
                v6::MessageType::Advertise => "advertise",
                v6::MessageType::Request => "request",
                v6::MessageType::Confirm => "confirm",
                v6::MessageType::Decline => "decline",
                v6::MessageType::Renew => "renew",
                v6::MessageType::Rebind => "rebind",
                v6::MessageType::Release => "release",
                v6::MessageType::Reply => "reply",
                _ => {
                    log::warn!("Got unknown message type {:?}", self.0);
                    "unknown"
                }
            }
        )
    }
}

impl From<DhcpV6MessageType> for v6::MessageType {
    fn from(v: DhcpV6MessageType) -> Self {
        v.0
    }
}

impl From<v6::MessageType> for DhcpV6MessageType {
    fn from(v: v6::MessageType) -> Self {
        Self(v)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct DhcpV6Message {
    pub(crate) msg_type: DhcpV6MessageType,
    pub(crate) lease: Option<DhcpV6Lease>,
    pub(crate) config: DhcpV6Config,
    pub(crate) xid: [u8; 3],
    elapsed_time: u16,
}

impl DhcpV6Message {
    pub(crate) fn new(
        config: &DhcpV6Config,
        msg_type: DhcpV6MessageType,
        xid: [u8; 3],
    ) -> Self {
        Self {
            msg_type,
            config: config.clone(),
            lease: None,
            xid,
            elapsed_time: 0,
        }
    }

    pub(crate) fn load_lease(
        &mut self,
        lease: DhcpV6Lease,
    ) -> Result<(), DhcpError> {
        validate_lease(&self.config, &lease)?;
        self.lease = Some(lease);
        Ok(())
    }

    pub(crate) fn to_dhcp_pkg(&self) -> Result<Vec<u8>, DhcpError> {
        let mut dhcp_msg =
            v6::Message::new_with_id(self.msg_type.into(), self.xid);

        dhcp_msg
            .opts_mut()
            .insert(DhcpOption::ClientId(self.config.duid.to_vec()));

        match self.config.ia_type {
            DhcpV6IaType::NonTemporaryAddresses => {
                dhcp_msg.opts_mut().insert(DhcpOption::IANA(v6::IANA {
                    id: self
                        .lease
                        .as_ref()
                        .map(|l| l.iaid)
                        .unwrap_or(DEFAULT_IAID),
                    // Required by RFC 8415 section 21.4
                    t1: 0,
                    // Required by RFC 8415 section 21.4
                    t2: 0,
                    opts: self
                        .lease
                        .as_ref()
                        .map(gen_iaadr_dhcp_opt)
                        .unwrap_or_default(),
                }))
            }
            DhcpV6IaType::TemporaryAddresses => {
                dhcp_msg.opts_mut().insert(DhcpOption::IATA(v6::IATA {
                    id: self
                        .lease
                        .as_ref()
                        .map(|l| l.iaid)
                        .unwrap_or(DEFAULT_IAID),
                    opts: self
                        .lease
                        .as_ref()
                        .map(gen_iaadr_dhcp_opt)
                        .unwrap_or_default(),
                }))
            }
            DhcpV6IaType::PrefixDelegation => {
                dhcp_msg.opts_mut().insert(DhcpOption::IAPD(v6::IAPD {
                    id: self
                        .lease
                        .as_ref()
                        .map(|l| l.iaid)
                        .unwrap_or(DEFAULT_IAID),
                    // Required by RFC 8415 section 21.21
                    t1: 0,
                    // Required by RFC 8415 section 21.21
                    t2: 0,
                    opts: self
                        .lease
                        .as_ref()
                        .map(gen_iaadr_dhcp_opt)
                        .unwrap_or_default(),
                }))
            }
        }

        match self.msg_type {
            DhcpV6MessageType::SOLICIT | DhcpV6MessageType::REBIND => (),
            DhcpV6MessageType::REQUEST | DhcpV6MessageType::RENEW => {
                if let Some(lease) = self.lease.as_ref() {
                    dhcp_msg
                        .opts_mut()
                        .insert(DhcpOption::ServerId(lease.srv_duid.clone()));
                } else {
                    return Err(DhcpError::new(
                        ErrorKind::InvalidArgument,
                        "No DHCP lease found for DHCP request, please run \
                        DhcpV6Message::load_lease() first"
                            .to_string(),
                    ));
                }
            }
            _ => {
                log::error!(
                    "BUG: Invalid DhcpV6MessageType {:?}",
                    self.msg_type
                );
            }
        }

        if self.elapsed_time > 0 {
            dhcp_msg
                .opts_mut()
                .insert(DhcpOption::ElapsedTime(self.elapsed_time));
        }

        log::debug!("DHCP message {:?}", dhcp_msg);

        let mut dhcp_msg_buff = Vec::new();
        let mut e = v6::Encoder::new(&mut dhcp_msg_buff);
        dhcp_msg.encode(&mut e)?;
        Ok(dhcp_msg_buff)
    }

    pub(crate) fn from_dhcp_pkg(payload: &[u8]) -> Result<Self, DhcpError> {
        let v6_dhcp_msg = v6::Message::decode(&mut Decoder::new(payload))
            .map_err(|decode_error| {
                let e = DhcpError::new(
                    ErrorKind::InvalidDhcpServerReply,
                    format!(
                        "Failed to parse DHCPv6 message from payload of pkg \
                        {payload:?}: {decode_error}"
                    ),
                );
                log::error!("{}", e);
                e
            })?;

        let ret = Self {
            lease: Some(DhcpV6Lease::try_from(&v6_dhcp_msg)?),
            msg_type: v6_dhcp_msg.msg_type().into(),
            xid: v6_dhcp_msg.xid(),
            ..Default::default()
        };
        log::debug!("Got reply DHCP message {:?}", ret);
        Ok(ret)
    }

    pub(crate) fn add_elapsed_time(&mut self, trans_begin_time: Instant) {
        self.elapsed_time =
            match u16::try_from(trans_begin_time.elapsed().as_secs() / 100) {
                Ok(i) => i,
                Err(_) => u16::MAX,
            };
    }
}

fn validate_lease(
    config: &DhcpV6Config,
    lease: &DhcpV6Lease,
) -> Result<(), DhcpError> {
    if lease.ia_type != config.ia_type {
        return Err(DhcpError::new(
            ErrorKind::InvalidArgument,
            format!(
                "DHCPv6 lease contains different IA type({}) with config({}) \
                DhcpV6Message::load_lease() with correct lease",
                lease.ia_type, config.ia_type
            ),
        ));
    }
    if lease.srv_duid.is_empty() {
        return Err(DhcpError::new(
            ErrorKind::InvalidArgument,
            "DHCPv6 lease contains empty server DUID, please run \
            DhcpV6Message::load_lease() with correct lease"
                .to_string(),
        ));
    }
    if lease.addr == Ipv6Addr::UNSPECIFIED {
        return Err(DhcpError::new(
            ErrorKind::InvalidArgument,
            "DHCPv6 lease contains invalid all zero lease \
            IPv6 address, please run DhcpV6Message::load_lease()
            with correct lease"
                .to_string(),
        ));
    }
    Ok(())
}

fn gen_iaadr_dhcp_opt(lease: &DhcpV6Lease) -> DhcpOptions {
    let mut ret = DhcpOptions::new();
    match lease.ia_type {
        DhcpV6IaType::TemporaryAddresses
        | DhcpV6IaType::NonTemporaryAddresses => {
            ret.insert(DhcpOption::IAAddr(v6::IAAddr {
                addr: lease.addr,
                // Set to 0 per RFC 8415 section 21.6
                preferred_life: 0,
                // Set to 0 per RFC 8415 section 21.6
                valid_life: 0,
                opts: DhcpOptions::new(),
            }));
        }
        DhcpV6IaType::PrefixDelegation => {
            ret.insert(DhcpOption::IAPrefix(v6::IAPrefix {
                prefix_len: lease.prefix_len,
                prefix_ip: lease.addr,
                // Set to 0 per RFC 8415 section 21.6
                preferred_lifetime: 0,
                // Set to 0 per RFC 8415 section 21.6
                valid_lifetime: 0,
                opts: DhcpOptions::new(),
            }));
        }
    }
    ret
}
