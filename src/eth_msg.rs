#[derive(Debug, PartialEq, Clone)]
pub struct EthernetMessage {
    src: u16,
    dst: u16,
    len: u16,
    sum: u16,
    payload: Vec<u8>,
}

impl EthernetMessage {
    pub fn new(src: u16, dst: u16, len: u16, payload: &[u8]) -> Self {

    }

    pub fn emit(&self, buffer: &mut [u8]) {

    }

    pub fn package_len(&self) -> usize {
        8 + self.payload.len()
    }
}
