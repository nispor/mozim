// SPDX-License-Identifier: Apache-2.0

mod dhcpv4;
mod dhcpv6;
mod error;
mod mac;
mod netlink;
mod time;

#[cfg(test)]
mod integ_tests;

pub(crate) use crate::time::DhcpTimer;
pub use crate::{
    dhcpv4::{
        DhcpV4ClasslessRoute, DhcpV4Client, DhcpV4Config, DhcpV4Lease,
        DhcpV4State,
    },
    dhcpv6::{
        DhcpV6Client, DhcpV6Config, DhcpV6Duid, DhcpV6DuidEn, DhcpV6DuidLl,
        DhcpV6DuidLlt, DhcpV6DuidUuid, DhcpV6IaType, DhcpV6Lease, DhcpV6Mode,
        DhcpV6State,
    },
    error::{DhcpError, ErrorKind},
};

// libc::ETH_ALEN
pub(crate) const ETH_ALEN: usize = 6;
