// SPDX-License-Identifier: Apache-2.0

use log::error;

use crate::{DhcpError, ErrorKind};

pub(crate) const BROADCAST_MAC_ADDRESS: [u8; 6] = [u8::MAX; 6];

pub(crate) fn mac_str_to_u8_array(mac: &str) -> Vec<u8> {
    let mut mac_bytes = Vec::new();
    for item in mac.split(':') {
        match u8::from_str_radix(item, 16) {
            Ok(i) => mac_bytes.push(i),
            Err(e) => {
                error!(
                    "Failed to convert to MAC address to bytes {mac:?}: {e}"
                );
                return Vec::new();
            }
        }
    }
    mac_bytes
}

pub(crate) fn mac_address_to_eth_mac_bytes(
    mac_address: &str,
) -> Result<[u8; libc::ETH_ALEN as usize], DhcpError> {
    let mut ret = [0u8; libc::ETH_ALEN as usize];
    let mac_bytes = mac_str_to_u8_array(mac_address);

    if mac_bytes.len() > libc::ETH_ALEN as usize {
        Err(DhcpError::new(
            ErrorKind::Bug,
            format!(
                "MAC address {} exceeded the max length {}",
                mac_address,
                libc::ETH_ALEN
            ),
        ))
    } else {
        ret.clone_from_slice(&mac_bytes);
        Ok(ret)
    }
}
