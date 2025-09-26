// SPDX-License-Identifier: Apache-2.0

use std::net::{IpAddr, Ipv6Addr};

use futures::stream::TryStreamExt;
use rtnetlink::packet_route::{address::AddressAttribute, link::LinkAttribute};

use crate::{DhcpError, ErrorKind};

pub(crate) async fn get_iface_index_mac(
    iface_name: &str,
) -> Result<(u32, Vec<u8>), DhcpError> {
    let (connection, handle, _) = rtnetlink::new_connection()?;

    tokio::spawn(connection);

    let mut links = handle
        .link()
        .get()
        .match_name(iface_name.to_string())
        .execute();

    while let Some(nl_msg) = links.try_next().await? {
        for nla in nl_msg.attributes {
            if let LinkAttribute::Address(mac) = nla {
                return Ok((nl_msg.header.index, mac));
            }
        }
    }
    Err(DhcpError::new(
        ErrorKind::InvalidArgument,
        format!("Interface {iface_name} not found"),
    ))
}

pub(crate) async fn get_iface_index(
    iface_name: &str,
) -> Result<u32, DhcpError> {
    let (connection, handle, _) = rtnetlink::new_connection()?;

    tokio::spawn(connection);

    let mut links = handle
        .link()
        .get()
        .match_name(iface_name.to_string())
        .execute();

    if let Some(nl_msg) = links.try_next().await? {
        return Ok(nl_msg.header.index);
    }
    Err(DhcpError::new(
        ErrorKind::InvalidArgument,
        format!("Interface {iface_name} not found"),
    ))
}

pub(crate) async fn get_link_local_addr(
    iface_index: u32,
) -> Result<Ipv6Addr, DhcpError> {
    let (connection, handle, _) = rtnetlink::new_connection()?;

    tokio::spawn(connection);

    let mut addrs = handle
        .address()
        .get()
        .set_link_index_filter(iface_index)
        .execute();

    while let Some(nl_msg) = addrs.try_next().await? {
        for attr in nl_msg.attributes {
            if let AddressAttribute::Address(IpAddr::V6(ip)) = attr {
                if is_unique_link_local(ip) {
                    return Ok(ip);
                }
            }
        }
    }
    Err(DhcpError::new(
        ErrorKind::InvalidArgument,
        format!("Interface with index {iface_index} not found"),
    ))
}

// Copy from Rust 1.84 code src/core/net/ip_addr.rs which is licensed under
// "Apache License, Version 2.0" and "MIT license":
// Please check https://www.rust-lang.org/policies/licenses for detail.
const fn is_unique_link_local(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}
