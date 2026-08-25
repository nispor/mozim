// SPDX-License-Identifier: Apache-2.0

use crate::{DhcpError, ErrorKind};

const DHCP_BPF_LEN: u16 = 11;

// libc are setting these constant as u32 which make our life worse
// as libc::sock_filter code is u16.
const BPF_B: u16 = 0x10;
const BPF_H: u16 = 0x08;

const BPF_ABS: u16 = 0x20;
const BPF_IND: u16 = 0x40;
const BPF_MSH: u16 = 0xa0;

const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;

const BPF_K: u16 = 0x00;

const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;

const ETHERTYPE_IP: u32 = 0x0800;
const IPPROTO_UDP: u32 = 17;

const DHCPV4_DST_PORT: u32 = 68;
const ETHER_TYPE_POS: u32 = 12;
const IP_PROTO_POS: u32 = 23;
const IP_FRAGMENT_POS: u32 = 20;
const IP_HEADER_LEN_POS: u32 = 14;
const ETHER_HEADER_LEN: u32 = 14;
const DST_PORT_IN_IP_POS: u32 = 2;

const BPF_FILTER_RAW: [(u16, u8, u8, u32); DHCP_BPF_LEN as usize] = [
    // Load protocol type to A
    (BPF_LD | BPF_H | BPF_ABS, 0, 0, ETHER_TYPE_POS),
    // Move on if ETHERTYPE_IP, otherwise drop package
    (BPF_JMP | BPF_JEQ | BPF_K, 0, 8, ETHERTYPE_IP),
    // Load IPv4 protocol type to A
    (BPF_LD | BPF_B | BPF_ABS, 0, 0, IP_PROTO_POS),
    // Move on if UDP, otherwise drop package
    (BPF_JMP | BPF_JEQ | BPF_K, 0, 6, IPPROTO_UDP),
    // Load IPv4 flag and fragment offset
    (BPF_LD | BPF_H | BPF_ABS, 0, 0, IP_FRAGMENT_POS),
    // Drop packet which has MF (more fragments) set or has a nonzero
    // fragment offset.
    (BPF_JMP | BPF_JSET | BPF_K, 4, 0, 0x3fff),
    // Store IP header length to X
    (BPF_LDX | BPF_B | BPF_MSH, 0, 0, IP_HEADER_LEN_POS),
    // Load UDP destination port number to A
    (
        BPF_LD | BPF_H | BPF_IND,
        0,
        0,
        ETHER_HEADER_LEN + DST_PORT_IN_IP_POS,
    ),
    // Check whether destination port is DHCPV4_DST_PORT
    (BPF_JMP | BPF_JEQ | BPF_K, 0, 1, DHCPV4_DST_PORT),
    // Accept this package
    (BPF_RET, 0, 0, u32::MAX),
    // Drop this package
    (BPF_RET, 0, 0, 0x00000000),
];

pub(crate) fn apply_dhcp_bpf(fd: libc::c_int) -> Result<(), DhcpError> {
    let mut raw_filters = [libc::sock_filter {
        code: 0,
        jt: 0,
        jf: 0,
        k: 0,
    }; DHCP_BPF_LEN as usize];
    for (i, (code, jt, jf, k)) in BPF_FILTER_RAW.iter().enumerate() {
        raw_filters[i].code = *code;
        raw_filters[i].jt = *jt;
        raw_filters[i].jf = *jf;
        raw_filters[i].k = *k;
        log::debug!(
            "Registering BPF filter {code:#04x}, {jt}, {jf}, {k:#010x}"
        );
    }
    let bpf_filter = libc::sock_fprog {
        len: DHCP_BPF_LEN,
        filter: raw_filters.as_ptr() as *mut _,
    };

    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&bpf_filter as *const _) as *const libc::c_void,
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let e = DhcpError::new(
            ErrorKind::Bug,
            format!(
                "Failed to apply socket BPF filter, error: {:?}",
                nix::errno::Errno::last()
            ),
        );
        log::error!("{e}");
        Err(e)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const CLASS_LD: u16 = 0x00;
    const CLASS_LDX: u16 = 0x01;
    const CLASS_JMP: u16 = 0x05;
    const CLASS_RET: u16 = 0x06;

    const MODE_ABS: u16 = 0x20;
    const MODE_IND: u16 = 0x40;
    const MODE_MSH: u16 = 0xa0;

    const SIZE_B: u16 = 0x10;
    const SIZE_H: u16 = 0x08;

    fn load_h(packet: &[u8], offset: usize) -> u32 {
        if offset + 2 > packet.len() {
            0
        } else {
            u16::from_be_bytes([packet[offset], packet[offset + 1]]) as u32
        }
    }

    fn run_filter(filter: &[(u16, u8, u8, u32)], packet: &[u8]) -> u32 {
        let mut pc = 0usize;
        let mut a = 0u32;
        let mut x = 0u32;

        while pc < filter.len() {
            let (code, jt, jf, k) = filter[pc];
            let class = code & 0x07;
            let size = code & 0x18;
            let mode = code & 0xe0;

            match class {
                CLASS_LD if mode == MODE_ABS && size == SIZE_B => {
                    a = *packet.get(k as usize).unwrap_or(&0) as u32;
                }
                CLASS_LD if mode == MODE_ABS && size == SIZE_H => {
                    a = load_h(packet, k as usize);
                }
                CLASS_LD if mode == MODE_IND && size == SIZE_H => {
                    a = load_h(packet, (x + k) as usize);
                }
                CLASS_LDX if mode == MODE_MSH => {
                    x = (*packet.get(k as usize).unwrap_or(&0) as u32 & 0x0f)
                        << 2;
                }
                CLASS_JMP if code & 0xf0 == BPF_JEQ => {
                    pc += 1;
                    if a == k {
                        pc += jt as usize;
                    } else {
                        pc += jf as usize;
                    }
                    continue;
                }
                CLASS_JMP if code & 0xf0 == BPF_JSET => {
                    pc += 1;
                    if a & k != 0 {
                        pc += jt as usize;
                    } else {
                        pc += jf as usize;
                    }
                    continue;
                }
                CLASS_RET => return k,
                _ => return 0,
            }
            pc += 1;
        }
        0
    }

    fn dhcp_frame(frag_bytes: [u8; 2]) -> Vec<u8> {
        let mut frame = vec![0u8; 300];
        frame[12..14].copy_from_slice(&[0x08, 0x00]);
        frame[14] = 0x45;
        frame[20..22].copy_from_slice(&frag_bytes);
        frame[23] = IPPROTO_UDP as u8;
        frame[36..38].copy_from_slice(&[0x00, 0x44]);
        frame
    }

    #[test]
    fn test_filter_accepts_udp_dhcp_packet() {
        assert_eq!(run_filter(&BPF_FILTER_RAW, &dhcp_frame([0, 0])), u32::MAX);
    }

    #[test]
    fn test_filter_rejects_mf_set_packet() {
        assert_eq!(run_filter(&BPF_FILTER_RAW, &dhcp_frame([0x20, 0])), 0);
    }

    #[test]
    fn test_filter_rejects_nonzero_fragment_offset() {
        assert_eq!(run_filter(&BPF_FILTER_RAW, &dhcp_frame([0, 1])), 0);
    }

    #[test]
    fn test_filter_accepts_df_set_packet() {
        assert_eq!(
            run_filter(&BPF_FILTER_RAW, &dhcp_frame([0x40, 0])),
            u32::MAX
        );
    }
}
