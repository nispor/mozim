use std::net::Ipv4Addr;

use rand;
use rand::Rng;

use crate::DhcpError;
use crate::traits::Emitable;


const MINIMUM_OPTION_LENGTH: usize = 312;

// RFC 2131
const BOOTREQEST: u8 = 1;
const BOOTREPLY: u8 = 2;
const CHADDR_LEN: usize = 16;
const SNAME_LEN: usize = 64;
const FILE_LEN: usize = 128;

// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
const HW_TYPE_ETHERNET: u8 = 1;

const ETHERNET_HW_ADDR_LEN: u8 = 6;

#[derive(Debug, PartialEq, Clone)]
pub struct Dhcpv4Option {}

impl Emitable for Dhcpv4Option {
    fn emit(&self, buffer: &mut [u8]) {
        // BUG: Network Padding
        todo!()
    }

    fn buffer_len(&self) -> usize {
        // BUG: Network Padding
        MINIMUM_OPTION_LENGTH
    }
}
