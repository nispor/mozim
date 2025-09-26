// SPDX-License-Identifier: Apache-2.0

use crate::{DhcpError, ErrorKind, ETH_ALEN};

pub(crate) const BROADCAST_MAC_ADDRESS: [u8; ETH_ALEN] = [u8::MAX; ETH_ALEN];

pub(crate) fn parse_mac(mac: &str) -> Result<Vec<u8>, DhcpError> {
    let mut mac_bytes = Vec::new();
    for item in mac.split(':') {
        match u8::from_str_radix(item, 16) {
            Ok(i) => mac_bytes.push(i),
            Err(_) => {
                return Err(DhcpError::new(
                    ErrorKind::InvalidArgument,
                    format!(
                        "Invalid MAC address {mac}, expecting format \
                         01:02:2a:2c:f7:04"
                    ),
                ));
            }
        }
    }
    Ok(mac_bytes)
}
