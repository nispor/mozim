// SPDX-License-Identifier: Apache-2.0

#[cfg(all(test, feature = "netlink"))]
mod dhcpv4;
#[cfg(all(test, feature = "netlink"))]
mod dhcpv4_proxy;
#[cfg(all(test, feature = "netlink"))]
mod dhcpv6;
#[cfg(all(test, not(feature = "netlink")))]
mod no_netlink;

mod env;
