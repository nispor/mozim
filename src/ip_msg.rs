use crate::EthernetMessage;

#[derive(Debug, PartialEq, Clone)]
pub struct Ipv4HeaderOption {
    pub copied: bool,
    pub class: u8,
    pub number: u8,
    pub length: u8,
    pub payload: Vec<[u8]>
}

#[derive(Debug, PartialEq, Clone)]
pub struct Ipv4Header {
    pub version: u8,
    pub header_length: u8,
    pub type_of_service: u8,
    pub length: u16,
    pub indentification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub time_to_live: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
    pub options: Vec<Ipv4HeaderOption>,
}

impl Ipv4Header {
    pub fn emit(&self, buffer: &mut [u8]) {

    }

    pub fn package_len() -> usize {
        0
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Ipv4Message {
    pub header: Ipv4Header,
    pub payload: Vec<EthernetMessage>

}

impl Ipv4Message {
    pub fn new() -> Self {
        Ipv4Message {}
    }
    pub fn emit(&self, buffer: &mut [u8]) {}

    pub fn package_len() -> usize {
        0
    }
}
