// SPDX-License-Identifier: Apache-2.0

mod buffer;
mod dhcpv4;
mod dhcpv6;
mod error;
mod mac;
#[cfg(feature = "netlink")]
mod netlink;
mod time;

#[cfg(test)]
mod integ_tests;

pub(crate) use crate::{
    buffer::{Buffer, BufferMut},
    time::DhcpTimer,
};
pub use crate::{
    dhcpv4::{
        DhcpV4ClasslessRoute, DhcpV4Client, DhcpV4Config, DhcpV4Lease,
        DhcpV4MessageType, DhcpV4Option, DhcpV4OptionCode, DhcpV4OptionUnknown,
        DhcpV4State,
    },
    dhcpv6::{
        DhcpV6Client, DhcpV6Config, DhcpV6Duid, DhcpV6DuidEnterpriseNumber,
        DhcpV6DuidLinkLayerAddr, DhcpV6DuidLinkLayerAddrPlusTime,
        DhcpV6DuidUuid, DhcpV6IaType, DhcpV6Lease, DhcpV6Mode, DhcpV6Option,
        DhcpV6OptionCode, DhcpV6OptionIaAddr, DhcpV6OptionIaNa,
        DhcpV6OptionIaPd, DhcpV6OptionIaPrefix, DhcpV6OptionIaTa,
        DhcpV6OptionNtpServer, DhcpV6OptionStatus, DhcpV6OptionStatusCode,
        DhcpV6OptionUnknown, DhcpV6State,
    },
    error::{DhcpError, ErrorContext, ErrorKind},
};

// libc::ETH_ALEN
pub(crate) const ETH_ALEN: usize = 6;
