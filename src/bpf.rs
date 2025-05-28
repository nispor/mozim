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
    // Drop package which has MF(more fragment) set is 1 or is fragment
    (BPF_JMP | BPF_JSET | BPF_K, 4, 0, 0x1fff),
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
