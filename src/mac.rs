// SPDX-License-Identifier: Apache-2.0

use crate::{DhcpError, ErrorKind, ETH_ALEN};

pub(crate) const BROADCAST_MAC_ADDRESS: [u8; ETH_ALEN] = [u8::MAX; ETH_ALEN];

fn invalid_mac_err(mac: &str) -> DhcpError {
    DhcpError::new(
        ErrorKind::InvalidArgument,
        format!(
            "Invalid MAC address {mac}, expecting format 01:02:2a:2c:f7:04"
        ),
    )
}

pub(crate) fn parse_mac(mac: &str) -> Result<[u8; ETH_ALEN], DhcpError> {
    let mut items = mac.split(':');
    let mut mac_bytes = [0u8; ETH_ALEN];
    for slot in &mut mac_bytes {
        match items
            .next()
            .and_then(|item| u8::from_str_radix(item, 16).ok())
        {
            Some(i) => *slot = i,
            None => return Err(invalid_mac_err(mac)),
        }
    }
    if items.next().is_some() {
        return Err(invalid_mac_err(mac));
    }
    Ok(mac_bytes)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_mac_valid() {
        assert_eq!(
            parse_mac("01:02:2a:2c:f7:04").unwrap(),
            [0x01, 0x02, 0x2a, 0x2c, 0xf7, 0x04]
        );
        assert_eq!(
            parse_mac("AA:BB:CC:DD:EE:FF").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
    }

    #[test]
    fn test_parse_mac_rejects_wrong_byte_count() {
        assert!(parse_mac("01:02:2a:2c:f7").is_err());
        assert!(parse_mac("01:02:2a:2c:f7:04:05").is_err());
        assert!(parse_mac("").is_err());
        assert!(parse_mac("01::04").is_err());
    }

    #[test]
    fn test_parse_mac_rejects_invalid_hex() {
        assert!(parse_mac("01:02:2a:2c:f7:ZZ").is_err());
        assert!(parse_mac("gg:02:2a:2c:f7:04").is_err());
    }
}
