// SPDX-License-Identifier: Apache-2.0

use std::time::Instant;

use super::option::DhcpV6Options;
use crate::{
    buffer::{Buffer, BufferMut},
    DhcpError, DhcpV6Duid, DhcpV6IaType, DhcpV6Lease, DhcpV6Option,
    DhcpV6OptionIaAddr, DhcpV6OptionIaNa, DhcpV6OptionIaPd, DhcpV6OptionIaTa,
    ErrorContext, ErrorKind,
};

/// DHCPv6 Message Type
///
/// Defined by RFC 8415 - 7.3. DHCP Message Types
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash, Default)]
#[non_exhaustive]
#[repr(u8)]
pub(crate) enum DhcpV6MessageType {
    #[default]
    Solicit = 1,
    Advertise = 2,
    Request = 3,
    Confirm = 4,
    Renew = 5,
    Rebind = 6,
    Reply = 7,
    Release = 8,
    Decline = 9,
    Reconfigure = 10,
    InformationRequest = 11,
    RelayForward = 12,
    RelayReply = 13,
}

impl std::fmt::Display for DhcpV6MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}",
            match self {
                DhcpV6MessageType::Solicit => "Solicit",
                DhcpV6MessageType::Advertise => "Advertise",
                DhcpV6MessageType::Request => "Request",
                DhcpV6MessageType::Confirm => "Confirm",
                DhcpV6MessageType::Renew => "Renew",
                DhcpV6MessageType::Rebind => "Rebind",
                DhcpV6MessageType::Reply => "Reply",
                DhcpV6MessageType::Release => "Release",
                DhcpV6MessageType::Decline => "Decline",
                DhcpV6MessageType::Reconfigure => "Reconfigure",
                DhcpV6MessageType::InformationRequest => "Information-request",
                DhcpV6MessageType::RelayForward => "Relay-forward",
                DhcpV6MessageType::RelayReply => "Relay-reply",
            }
        )
    }
}

impl From<DhcpV6MessageType> for u8 {
    fn from(v: DhcpV6MessageType) -> u8 {
        v as u8
    }
}

impl std::convert::TryFrom<u8> for DhcpV6MessageType {
    type Error = DhcpError;

    fn try_from(d: u8) -> Result<Self, DhcpError> {
        match d {
            d if d == Self::Solicit as u8 => Ok(Self::Solicit),
            d if d == Self::Advertise as u8 => Ok(Self::Advertise),
            d if d == Self::Request as u8 => Ok(Self::Request),
            d if d == Self::Confirm as u8 => Ok(Self::Confirm),
            d if d == Self::Renew as u8 => Ok(Self::Renew),
            d if d == Self::Rebind as u8 => Ok(Self::Rebind),
            d if d == Self::Reply as u8 => Ok(Self::Reply),
            d if d == Self::Release as u8 => Ok(Self::Release),
            d if d == Self::Decline as u8 => Ok(Self::Decline),
            d if d == Self::Reconfigure as u8 => Ok(Self::Reconfigure),
            d if d == Self::InformationRequest as u8 => {
                Ok(Self::InformationRequest)
            }
            d if d == Self::RelayForward as u8 => Ok(Self::RelayForward),
            d if d == Self::RelayReply as u8 => Ok(Self::RelayReply),
            _ => Err(DhcpError::new(
                ErrorKind::NotSupported,
                format!("DHCPv6 message type {d} is not supported"),
            )),
        }
    }
}

const DHCPV6_TRANSACTION_ID_LEN: usize = 3;

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub(crate) struct DhcpV6Message {
    pub(crate) msg_type: DhcpV6MessageType,
    pub(crate) xid: [u8; DHCPV6_TRANSACTION_ID_LEN],
    pub(crate) options: DhcpV6Options,
}

impl DhcpV6Message {
    pub(crate) fn new(
        msg_type: DhcpV6MessageType,
        xid: u32,
        duid: &DhcpV6Duid,
        trans_begin_time: &Instant,
    ) -> Self {
        let mut ret = Self {
            msg_type,
            xid: [0; DHCPV6_TRANSACTION_ID_LEN],
            options: DhcpV6Options::new(),
        };
        ret.xid.copy_from_slice(&xid.to_be_bytes()[1..]);
        ret.options.insert(DhcpV6Option::ElapsedTime(
            trans_begin_time.elapsed().as_millis() as u16 / 10,
        ));
        ret.options.insert(DhcpV6Option::ClientId(duid.clone()));
        ret
    }

    pub(crate) fn xid(&self) -> u32 {
        let mut ret = [0u8; 4];
        ret[1..].copy_from_slice(&self.xid);
        u32::from_be_bytes(ret)
    }

    pub(crate) fn load_lease(&mut self, lease: &DhcpV6Lease) {
        self.options
            .insert(DhcpV6Option::ServerId(lease.srv_duid.clone()));

        match lease.ia_type {
            Some(DhcpV6IaType::NonTemporaryAddresses) => {
                self.options
                    .insert(DhcpV6Option::IANA(DhcpV6OptionIaNa::new(
                        lease.iaid,
                        lease.t1_sec,
                        lease.t2_sec,
                        DhcpV6OptionIaAddr::new(
                            lease.address,
                            lease.preferred_time_sec,
                            lease.valid_time_sec,
                        ),
                    )))
            }
            Some(DhcpV6IaType::TemporaryAddresses) => {
                self.options
                    .insert(DhcpV6Option::IATA(DhcpV6OptionIaTa::new(
                        lease.iaid,
                        DhcpV6OptionIaAddr::new(
                            lease.address,
                            lease.preferred_time_sec,
                            lease.valid_time_sec,
                        ),
                    )))
            }
            Some(DhcpV6IaType::PrefixDelegation) => {
                self.options
                    .insert(DhcpV6Option::IAPD(DhcpV6OptionIaPd::new(
                        lease.address,
                        lease.prefix_len,
                    )));
            }
            None => (),
        }
    }

    pub(crate) fn parse(payload: &[u8]) -> Result<Self, DhcpError> {
        let mut buf = Buffer::new(payload);

        let mut ret = Self {
            msg_type: buf
                .get_u8()
                .context("Invalid DHCPv6 message type")?
                .try_into()?,
            ..Default::default()
        };

        ret.xid.copy_from_slice(
            buf.get_bytes(DHCPV6_TRANSACTION_ID_LEN)
                .context("Invalid DHCPv6 message transaction-id")?,
        );
        ret.options = DhcpV6Options::parse(&mut buf)?;
        log::debug!("Got reply DHCP message {ret:?}");
        Ok(ret)
    }

    pub(crate) fn emit(&self) -> Vec<u8> {
        let mut buf = BufferMut::new();
        buf.write_u8(self.msg_type.into());
        buf.write_bytes(&self.xid);
        self.options.emit(&mut buf);
        buf.data
    }
}
