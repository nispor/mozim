use crate::{DhcpError, ErrorKind};

const DHCP_BPF_LEN: u16 = 11;

// Using the output of `tcpdump -dd 'ip and udp dst port 68'`
const BPF_FILTER_RAW: [(u16, u8, u8, u32); DHCP_BPF_LEN as usize] = [
    (0x28, 0, 0, 0x0000000c),
    (0x15, 0, 8, 0x00000800),
    (0x30, 0, 0, 0x00000017),
    (0x15, 0, 6, 0x00000011),
    (0x28, 0, 0, 0x00000014),
    (0x45, 4, 0, 0x00001fff),
    (0xb1, 0, 0, 0x0000000e),
    (0x48, 0, 0, 0x00000010),
    (0x15, 0, 1, 0x00000044),
    (0x6, 0, 0, 0x00040000),
    (0x6, 0, 0, 0x00000000),
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
    }
    let bpf_filter = libc::sock_fprog {
        len: DHCP_BPF_LEN,
        filter: (&raw_filters).as_ptr() as *mut _,
    };

    unsafe {
        let rc = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&bpf_filter as *const _) as *const libc::c_void,
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        );
        if rc != 0 {
            return Err(DhcpError::new(
                ErrorKind::Bug,
                format!("Failed to apply socket BPF filter, error: {}", rc),
            ));
        }
    }
    Ok(())
}
