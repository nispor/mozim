// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;

use crate::{event::DhcpEvent, DhcpError, ErrorKind};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum DhcpV4Event {
    RawPackageIn = 1,
    UdpPackageIn,
    DiscoveryTimeout,
    RequestTimeout,
    Timeout,
    Renew,
    RenewRetry,
    Rebind,
    RebindRetry,
    LeaseExpired,
}

impl From<DhcpV4Event> for u64 {
    fn from(v: DhcpV4Event) -> u64 {
        v as u64
    }
}

impl TryFrom<u64> for DhcpV4Event {
    type Error = DhcpError;
    fn try_from(v: u64) -> Result<Self, DhcpError> {
        match v {
            x if x == Self::RawPackageIn as u64 => Ok(Self::RawPackageIn),
            x if x == Self::UdpPackageIn as u64 => Ok(Self::UdpPackageIn),
            x if x == Self::DiscoveryTimeout as u64 => {
                Ok(Self::DiscoveryTimeout)
            }
            x if x == Self::RequestTimeout as u64 => Ok(Self::RequestTimeout),
            x if x == Self::Timeout as u64 => Ok(Self::Timeout),
            x if x == Self::Renew as u64 => Ok(Self::Renew),
            x if x == Self::RenewRetry as u64 => Ok(Self::RenewRetry),
            x if x == Self::Rebind as u64 => Ok(Self::Rebind),
            x if x == Self::RebindRetry as u64 => Ok(Self::RebindRetry),
            x if x == Self::LeaseExpired as u64 => Ok(Self::LeaseExpired),
            _ => {
                let e = DhcpError::new(
                    ErrorKind::Bug,
                    format!("Got unexpected event ID {v}"),
                );
                log::error!("{e}");
                Err(e)
            }
        }
    }
}

impl std::fmt::Display for DhcpV4Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::RawPackageIn => "RawPackageIn",
                Self::UdpPackageIn => "UdpPackageIn",
                Self::DiscoveryTimeout => "DiscoveryTimeout",
                Self::RequestTimeout => "RequestTimeout",
                Self::Timeout => "Timeout",
                Self::Renew => "Renew",
                Self::RenewRetry => "RenewRetry",
                Self::Rebind => "Rebind",
                Self::RebindRetry => "RebindRetry",
                Self::LeaseExpired => "LeaseExpired",
            }
        )
    }
}

impl DhcpEvent for DhcpV4Event {}
