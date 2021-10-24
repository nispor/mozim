use crate::ip_msg::Ipv4Message;
use byteorder::{BigEndian};

#[derive(Debug, PartialEq, Clone)]
struct UdpHeader {
    src: u16,
    dst: u16,
    len: u16,
    sum: u16,
}

impl UdpMessage {
    pub fn emit(&self, buffer: &mut [u8]) {
        BigEndian::write_u16(&mut buffer[0..2], self.src);
        BigEndian::write_u16(&mut buffer[2..4], self.dst);
        BigEndian::write_u16(&mut buffer[4..6], self.len);
        BigEndian::write_u16(&mut buffer[6..8], self.sum);
    }

    pub fn buffer_len() -> usize {
        8
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct UdpMessage {
    header: UdpHeader,
    payload: Ipv4Message,
}

impl UdpMessage {
    pub fn new(src: u16, dst: u16, len: u16, payload: Ipv4Message) -> Self {
        UdpMessage {
            header: UdpHeader {
                src,
                dst,
                len,
                sum: 0, // TODO: UDP checksum disabled. please enable it.
            },
            payload: payload,
        }
    }

    pub fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.payload.emit(&mut buffer[self.header.buffer_len()..]);
    }

    pub fn buffer_len() -> usize {
        UdpHeader.buffer_len() + payload.buffer_len()
    }
}
