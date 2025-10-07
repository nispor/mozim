// SPDX-License-Identifier: Apache-2.0

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{DhcpError, ErrorKind};

#[derive(Debug)]
pub(crate) struct Buffer<'a> {
    index: usize,
    data: &'a [u8],
}

impl<'a> Buffer<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { index: 0, data }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.remain_len() == 0
    }

    pub(crate) fn remain_len(&self) -> usize {
        if self.index > self.data.len() {
            0
        } else {
            self.data.len() - self.index
        }
    }

    pub(crate) fn get_u8(&mut self) -> Result<u8, DhcpError> {
        if self.is_empty() {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                "Remain buffer not enough for getting u8".to_string(),
            ));
        }
        let ret = self.data[self.index];
        self.index += 1;
        Ok(ret)
    }

    pub(crate) fn get_u16_be(&mut self) -> Result<u16, DhcpError> {
        if self.remain_len() < 2 {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                "Remain buffer not enough for getting u16".to_string(),
            ));
        }
        let ret = u16::from_be_bytes([
            self.data[self.index],
            self.data[self.index + 1],
        ]);
        self.index += 2;
        Ok(ret)
    }

    pub(crate) fn get_u32_be(&mut self) -> Result<u32, DhcpError> {
        if self.remain_len() < 4 {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                "Remain buffer not enough for getting u32".to_string(),
            ));
        }
        let ret = u32::from_be_bytes([
            self.data[self.index],
            self.data[self.index + 1],
            self.data[self.index + 2],
            self.data[self.index + 3],
        ]);
        self.index += 4;
        Ok(ret)
    }

    pub(crate) fn get_u128_be(&mut self) -> Result<u128, DhcpError> {
        if self.remain_len() < 16 {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                "Remain buffer not enough for getting u128".to_string(),
            ));
        }
        let ret = u128::from_be_bytes([
            self.data[self.index],
            self.data[self.index + 1],
            self.data[self.index + 2],
            self.data[self.index + 3],
            self.data[self.index + 4],
            self.data[self.index + 5],
            self.data[self.index + 6],
            self.data[self.index + 7],
            self.data[self.index + 8],
            self.data[self.index + 9],
            self.data[self.index + 10],
            self.data[self.index + 11],
            self.data[self.index + 12],
            self.data[self.index + 13],
            self.data[self.index + 14],
            self.data[self.index + 15],
        ]);
        self.index += 16;
        Ok(ret)
    }

    pub(crate) fn get_bytes(&mut self, len: usize) -> Result<&[u8], DhcpError> {
        if self.remain_len() < len {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!(
                    "Remain buffer not enough for getting {len} bytes array"
                ),
            ));
        }
        let ret = &self.data[self.index..self.index + len];
        self.index += len;
        Ok(ret)
    }

    pub(crate) fn get_ipv4(&mut self) -> Result<Ipv4Addr, DhcpError> {
        if self.remain_len() < 4 {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                "Remain buffer not enough for getting IPv4 address".to_string(),
            ));
        }
        let ret = Ipv4Addr::new(
            self.data[self.index],
            self.data[self.index + 1],
            self.data[self.index + 2],
            self.data[self.index + 3],
        );
        self.index += 4;
        Ok(ret)
    }

    pub(crate) fn get_ipv6(&mut self) -> Result<Ipv6Addr, DhcpError> {
        if self.remain_len() < 16 {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                "Remain buffer not enough for getting IPv6 address".to_string(),
            ));
        }
        let ret = Ipv6Addr::new(
            // Already checked the size.
            self.get_u16_be().unwrap(),
            self.get_u16_be().unwrap(),
            self.get_u16_be().unwrap(),
            self.get_u16_be().unwrap(),
            self.get_u16_be().unwrap(),
            self.get_u16_be().unwrap(),
            self.get_u16_be().unwrap(),
            self.get_u16_be().unwrap(),
        );
        Ok(ret)
    }

    /// Truncate the string to first NULL(0) char if found.
    /// Move the pointer to fix_size.
    pub(crate) fn get_string_with_null(
        &mut self,
        fix_size: usize,
    ) -> Result<String, DhcpError> {
        if self.remain_len() < fix_size {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!(
                    "Remain buffer not enough for getting {fix_size} bytes \
                     string"
                ),
            ));
        }
        let pos = if let Some(p) = self.data[self.index..self.index + fix_size]
            .iter()
            .position(|c| *c == 0)
        {
            p
        } else {
            fix_size
        };
        let vec = self.data[self.index..self.index + pos].to_vec();
        self.index += fix_size;

        String::from_utf8(vec).map_err(|e| {
            DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!("Not valid UTF-8 string: {e}"),
            )
        })
    }

    pub(crate) fn get_string_without_null(
        &mut self,
        size: usize,
    ) -> Result<String, DhcpError> {
        if self.remain_len() < size {
            return Err(DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!(
                    "Remain buffer not enough for getting {size} bytes string"
                ),
            ));
        }
        let vec = self.data[self.index..self.index + size].to_vec();
        self.index += size;

        String::from_utf8(vec).map_err(|e| {
            DhcpError::new(
                ErrorKind::InvalidDhcpMessage,
                format!("Not valid UTF-8 string: {e}"),
            )
        })
    }

    pub(crate) fn get_remains(&mut self) -> &[u8] {
        if self.index > self.data.len() {
            &[]
        } else {
            &self.data[self.index..]
        }
    }
}

pub(crate) struct BufferMut {
    pub(crate) data: Vec<u8>,
}

impl BufferMut {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    pub(crate) fn write_u8(&mut self, value: u8) {
        self.data.push(value);
    }

    pub(crate) fn write_u16_be(&mut self, value: u16) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn write_u32_be(&mut self, value: u32) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn write_u128_be(&mut self, value: u128) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn write_bytes(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    pub(crate) fn write_ipv4(&mut self, addr: Ipv4Addr) {
        self.data.extend_from_slice(&addr.octets());
    }

    pub(crate) fn write_ipv6(&mut self, addr: Ipv6Addr) {
        self.data.extend_from_slice(&addr.octets());
    }

    pub(crate) fn write_string_without_null(&mut self, value: &str) {
        self.data.extend_from_slice(value.as_bytes());
    }

    /// `max_size` include the trailing null. The truncate does not check
    /// UTF-8 boundary for now.
    pub(crate) fn write_string_with_null(
        &mut self,
        value: &str,
        fix_size: usize,
    ) {
        // TODO(Gris Ge): This function does not responsible for truncating in
        // the middle of single UTF-8 character. The Rust 1.91 has
        // `str::floor_char_boundary()` which could helps. Let's wait a while
        // for that rust version became popular.
        let value_bytes = if (value.len() + 1) > fix_size {
            &value.as_bytes()[..fix_size - 1]
        } else {
            value.as_bytes()
        };

        let remains = fix_size - value_bytes.len() - 1;

        self.data.extend_from_slice(value_bytes);
        if remains > 0 {
            self.data.extend_from_slice(vec![0u8; remains].as_slice());
        }
        self.write_u8(0);
    }
}
