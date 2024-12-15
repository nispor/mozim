// SPDX-License-Identifier: Apache-2.0

use std::net::Ipv6Addr;
use std::str::FromStr;

use nispor::{Ipv6AddrFlag, NetState, NetStateFilter, NetStateIfaceFilter};

use crate::{DhcpError, ErrorKind};

// We use thread to invoke nispor which has `tokio::block_on` which
// stop our async usage
pub(crate) fn get_nispor_iface(
    iface_name: &str,
    with_ip: bool,
) -> Result<nispor::Iface, DhcpError> {
    let iface_name = iface_name.to_string();
    match std::thread::spawn(move || {
        if iface_name.is_empty() {
            let e = DhcpError::new(
                ErrorKind::InvalidArgument,
                "Interface name not defined".to_string(),
            );
            log::error!("{}", e);
            return Err(e);
        }
        let mut filter = NetStateFilter::minimum();
        let mut iface_filter = NetStateIfaceFilter::minimum();
        iface_filter.iface_name = Some(iface_name.to_string());
        iface_filter.include_ip_address = with_ip;
        filter.iface = Some(iface_filter);

        let net_state = match NetState::retrieve_with_filter(&filter) {
            Ok(s) => s,
            Err(e) => {
                return Err(DhcpError::new(
                    ErrorKind::Bug,
                    format!("Failed to retrieve network state: {e}"),
                ))
            }
        };
        if let Some(iface) = net_state.ifaces.get(iface_name.as_str()) {
            Ok(iface.clone())
        } else {
            Err(DhcpError::new(
                ErrorKind::InvalidArgument,
                format!("Interface {iface_name} not found"),
            ))
        }
    })
    .join()
    {
        Ok(n) => Ok(n?),
        Err(e) => Err(DhcpError::new(
            ErrorKind::Bug,
            format!("Failed to invoke nispor thread: {e:?}"),
        )),
    }
}

// Search link-local address or global address:
//  * prefer link-local address over global
//  * Not allow address with tentative flag.
pub(crate) fn get_ipv6_addr_of_iface(
    iface: &nispor::Iface,
) -> Result<Ipv6Addr, DhcpError> {
    if let Some(addrs) = iface.ipv6.as_ref().map(|i| i.addresses.as_slice()) {
        if let Some(addr) = addrs
            .iter()
            .filter_map(|a| {
                if !a.flags.contains(&Ipv6AddrFlag::Tentative) {
                    Ipv6Addr::from_str(a.address.as_str()).ok()
                } else {
                    None
                }
            })
            .find(is_ipv6_unicast_link_local)
            .or_else(|| {
                addrs
                    .iter()
                    .filter_map(|a| {
                        if !a.flags.contains(&Ipv6AddrFlag::Tentative) {
                            Ipv6Addr::from_str(a.address.as_str()).ok()
                        } else {
                            None
                        }
                    })
                    .find(is_ipv6_unicast)
            })
        {
            Ok(addr)
        } else {
            Err(DhcpError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Failed to find unicast IPv6 address on \
                    interface {} which is required for DHCPv6",
                    iface.name
                ),
            ))
        }
    } else {
        Err(DhcpError::new(
            ErrorKind::InvalidArgument,
            format!(
                "Interface {} has no IPv6 address to start DHCPv6",
                iface.name
            ),
        ))
    }
}

// Copy from Rust official std::net::Ipv6Addr::is_unicast_link_local() which
// is experimental.
fn is_ipv6_unicast_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

// Copy from Rust official std::net::Ipv6Addr::is_multicast() which is
// experimental.
fn is_ipv6_unicast(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xff00) != 0xff00
}
