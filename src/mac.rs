use log::error;

pub(crate) fn mac_str_to_u8_array(mac: &str) -> Vec<u8> {
    let mut mac_bytes = Vec::new();
    for item in mac.split(':') {
        match u8::from_str_radix(item, 16) {
            Ok(i) => mac_bytes.push(i),
            Err(e) => {
                error!(
                    "Failed to convert to MAC address to bytes {:?}: {}",
                    mac, e
                );
                return Vec::new();
            }
        }
    }
    mac_bytes
}

