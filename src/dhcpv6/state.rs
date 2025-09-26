// SPDX-License-Identifier: Apache-2.0

use crate::DhcpV6Lease;

#[derive(Debug, PartialEq, Clone, Eq, Default)]
#[non_exhaustive]
pub enum DhcpV6State {
    /// Lease acquired, waiting on T1 timer.
    Done(Box<DhcpV6Lease>),
    /// Sent `Solicit` multicast packet, waiting DHCPv6 server `Advertise`
    /// message or `Reply` message for `OPTION_RAPID_COMMIT`.
    #[default]
    Solicit,
    /// Sent `Request` multicast(or unicast for `OPTION_UNICAST`) packet,
    /// waiting DHCPv6 server `Reply` message.
    Request,
    /// Sent `Renew` multicast(or unicast for `OPTION_UNICAST`) packet to the
    /// lease provider server, waiting DHCPv6 server `Reply` message.
    Renew,
    /// Sent `Renew` multicast packet, waiting DHCPv6 server `Reply` message.
    Rebind,
    //  Sent `Information-request` multicast packet, waiting DHCPv6 server
    //  `Reply` message.
    // InformationRequest,
}

impl std::fmt::Display for DhcpV6State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Done(lease) => write!(f, "done({})", lease.addr),
            Self::Solicit => write!(f, "solicit"),
            Self::Request => write!(f, "request"),
            Self::Renew => write!(f, "renew"),
            Self::Rebind => write!(f, "rebind"),
        }
    }
}

impl DhcpV6State {
    pub fn is_done(&self) -> bool {
        matches!(self, DhcpV6State::Done(_))
    }
}
