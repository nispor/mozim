use std::net::Ipv4Addr;

use rand;
use rand::Rng;

use crate::{traits::Emitable, DhcpError, Dhcpv4Option};

// RFC 2131
const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;
const CHADDR_LEN: usize = 16;
const SNAME_LEN: usize = 64;
const FILE_LEN: usize = 128;

// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
const HW_TYPE_ETHERNET: u8 = 1;

const ETHERNET_HW_ADDR_LEN: u8 = 6;

// RFC 2131:
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
//    +---------------+---------------+---------------+---------------+
//    |                            xid (4)                            |
//    +-------------------------------+-------------------------------+
//    |           secs (2)            |           flags (2)           |
//    +-------------------------------+-------------------------------+
//    |                          ciaddr  (4)                          |
//    +---------------------------------------------------------------+
//    |                          yiaddr  (4)                          |
//    +---------------------------------------------------------------+
//    |                          siaddr  (4)                          |
//    +---------------------------------------------------------------+
//    |                          giaddr  (4)                          |
//    +---------------------------------------------------------------+
//    |                                                               |
//    |                          chaddr  (16)                         |
//    |                                                               |
//    |                                                               |
//    +---------------------------------------------------------------+
//    |                                                               |
//    |                          sname   (64)                         |
//    +---------------------------------------------------------------+
//    |                                                               |
//    |                          file    (128)                        |
//    +---------------------------------------------------------------+
//    |                                                               |
//    |                          options (variable)                   |
//    +---------------------------------------------------------------+
#[derive(Debug, PartialEq, Clone)]
pub struct Dhcp4Message {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16, // Using of BROADCAST bit is discouraged by RFC 1542
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    siaddr: Ipv4Addr,
    giaddr: Ipv4Addr,
    hw_addr: String,   // DHCP chaddr
    host_name: String, // DHCP sname
    file: [u8; 128],
    options: Vec<Dhcpv4Option>,
}

impl Default for Dhcp4Message {
    fn default() -> Self {
        Self {
            op: 0,
            htype: 0,
            hlen: 0,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::new(0, 0, 0, 0),
            yiaddr: Ipv4Addr::new(0, 0, 0, 0),
            siaddr: Ipv4Addr::new(0, 0, 0, 0),
            giaddr: Ipv4Addr::new(0, 0, 0, 0),
            hw_addr: "".into(),
            host_name: "".into(),
            file: [0u8; 128],
            options: Vec::new(),
        }
    }
}

const POSITION_OP_START: usize = 0;
const POSITION_HTYPE_START: usize = 1;
const POSITION_HLEN_START: usize = 2;
const POSITION_HOPS_START: usize = 3;
const POSITION_XID_START: usize = 4;
const POSITION_SECS_START: usize = 8;
const POSITION_FLAGS_START: usize = 10;
const POSITION_CIADDR_START: usize = 12;
const POSITION_YIADDR_START: usize = 16;
const POSITION_SIADDR_START: usize = 20;
const POSITION_GIADDR_START: usize = 24;
const POSITION_CHADDR_START: usize = 28;
const POSITION_SNAME_START: usize = 44;
const POSITION_FILE_START: usize = 108;
const POSITION_OPTIONS_START: usize = 236;

const DHCP_OPTIONS_LENGTH_MINIMUM: usize = 312;

impl Emitable for Dhcp4Message {
    fn emit(&self, buffer: &mut [u8]) {
        // Assuming buffer bytes are all zero.
        buffer[POSITION_OP_START] = self.op;
        buffer[POSITION_HTYPE_START] = self.htype;
        buffer[POSITION_HLEN_START] = self.hlen;
        buffer[POSITION_HOPS_START] = self.hops;
        buffer[POSITION_XID_START..POSITION_SECS_START]
            .clone_from_slice(&self.xid.to_be_bytes());
        buffer[POSITION_SECS_START..POSITION_FLAGS_START]
            .clone_from_slice(&self.flags.to_be_bytes());
        buffer[POSITION_CIADDR_START..POSITION_YIADDR_START]
            .clone_from_slice(&self.ciaddr.octets());
        buffer[POSITION_YIADDR_START..POSITION_SIADDR_START]
            .clone_from_slice(&self.yiaddr.octets());
        buffer[POSITION_SIADDR_START..POSITION_GIADDR_START]
            .clone_from_slice(&self.siaddr.octets());
        buffer[POSITION_GIADDR_START..POSITION_CHADDR_START]
            .clone_from_slice(&self.giaddr.octets());
        buffer[POSITION_CHADDR_START..POSITION_SNAME_START]
            .clone_from_slice(&self.hw_addr.as_bytes());
        buffer[POSITION_SNAME_START..POSITION_FILE_START]
            .clone_from_slice(&self.host_name.as_bytes());
        buffer[POSITION_FILE_START..POSITION_OPTIONS_START]
            .clone_from_slice(&self.file);
        self.options
            .as_slice()
            .emit(&mut buffer[POSITION_OPTIONS_START..]);
    }

    fn buffer_len(&self) -> usize {
        POSITION_OPTIONS_START + self.options.as_slice().buffer_len()
    }
}

impl Dhcp4Message {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        Dhcp4Message {
            hlen: ETHERNET_HW_ADDR_LEN,
            xid: rng.gen(),
            ..Default::default()
        }
    }

    pub fn set_host_name(mut self, host_name: &str) -> Result<Self, DhcpError> {
        if host_name.as_bytes().len() >= SNAME_LEN {
            Err(DhcpError::invalid_argument(format!(
                "WARN: Specified host_name '{}' exceeded the maximum length {}",
                host_name,
                SNAME_LEN - 1
            )))
        } else {
            self.host_name = host_name.to_string();
            Ok(self)
        }
    }

    pub fn set_hw_addr(mut self, hw_addr: &str) -> Result<Self, DhcpError> {
        let hw_addr = hw_addr.replace(":", "").to_ascii_lowercase();
        if hw_addr.as_bytes().len() >= CHADDR_LEN {
            Err(DhcpError::invalid_argument(format!(
                "Specified hw_addr '{}' exceeded the maximum length {}",
                hw_addr,
                CHADDR_LEN - 1
            )))
        } else {
            self.hw_addr = hw_addr.to_string();
            Ok(self)
        }
    }

    pub fn request(mut self) -> Self {
        self.op = BOOTREQUEST;
        println!("{:?}", &self);
        self
    }
}
