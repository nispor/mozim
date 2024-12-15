// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;

use crate::{event::DhcpEvent, DhcpError, ErrorKind};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[non_exhaustive]
pub enum DhcpV6Event {
    UdpPackageIn = 1,
    TransmitWait,
    Timeout,
    Renew,
    Rebind,
    LeaseExpired,
}

impl From<DhcpV6Event> for u64 {
    fn from(v: DhcpV6Event) -> u64 {
        v as u64
    }
}

impl TryFrom<u64> for DhcpV6Event {
    type Error = DhcpError;
    fn try_from(v: u64) -> Result<Self, DhcpError> {
        match v {
            x if x == Self::UdpPackageIn as u64 => Ok(Self::UdpPackageIn),
            x if x == Self::TransmitWait as u64 => Ok(Self::TransmitWait),
            x if x == Self::Timeout as u64 => Ok(Self::Timeout),
            x if x == Self::Renew as u64 => Ok(Self::Renew),
            x if x == Self::Rebind as u64 => Ok(Self::Rebind),
            x if x == Self::LeaseExpired as u64 => Ok(Self::LeaseExpired),
            _ => {
                let e = DhcpError::new(
                    ErrorKind::Bug,
                    format!("Got unexpected event ID {v}"),
                );
                log::error!("{}", e);
                Err(e)
            }
        }
    }
}

impl std::fmt::Display for DhcpV6Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::UdpPackageIn => "UdpPackageIn",
                Self::TransmitWait => "TransmitWait",
                Self::Timeout => "Timeout",
                Self::Renew => "Renew",
                Self::Rebind => "Rebind",
                Self::LeaseExpired => "LeaseExpired",
            }
        )
    }
}

impl DhcpEvent for DhcpV6Event {}
