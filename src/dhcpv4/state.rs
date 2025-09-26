// SPDX-License-Identifier: Apache-2.0

use crate::DhcpV4Lease;

/// DHCPv4 Client State
/// RFC 2131 Table 4: Client messages from different states
#[derive(Debug, PartialEq, Clone, Eq, Default)]
pub enum DhcpV4State {
    /// DHCP lease acquired, waiting T1/T2 to refresh the lease
    Done(Box<DhcpV4Lease>),
    /// Sending broadcast DHCPDISCOVER to server and waiting DHCPOFFER
    #[default]
    InitReboot,
    /// Sending broadcast DHCPREQUEST to server and waiting DHCPACK
    Selecting,
    /// T1 expired, sending unicast DHCPREQUEST and waiting DHCPACK
    Renewing,
    /// T2 expired, sending broadcast DHCPREQUEST and waiting DHCPACK
    Rebinding,
}

impl std::fmt::Display for DhcpV4State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Done(lease) => write!(f, "done({})", lease.yiaddr),
            Self::InitReboot => write!(f, "init_reboot"),
            Self::Selecting => write!(f, "selecting"),
            Self::Renewing => write!(f, "renewing"),
            Self::Rebinding => write!(f, "rebinding"),
        }
    }
}

impl DhcpV4State {
    pub fn is_done(&self) -> bool {
        matches!(self, DhcpV4State::Done(_))
    }
}
