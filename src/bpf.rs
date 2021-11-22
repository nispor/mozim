use crate::{DhcpError, ErrorKind};

const DHCP_BPF_LEN: u16 = 13;

pub(crate) fn apply_dhcp_bpf(fd: libc::c_int) -> Result<(), DhcpError> {
    // Using the output of `tcpdump -dd 'ip and udp port 67'`
    let raw_filters: [libc::sock_filter; DHCP_BPF_LEN as usize] = [
        libc::sock_filter {
            code: 0x28,
            jt: 0,
            jf: 0,
            k: 0x0000000c,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 10,
            k: 0x00000800,
        },
        libc::sock_filter {
            code: 0x30,
            jt: 0,
            jf: 0,
            k: 0x00000017,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 8,
            k: 0x00000011,
        },
        libc::sock_filter {
            code: 0x28,
            jt: 0,
            jf: 0,
            k: 0x00000014,
        },
        libc::sock_filter {
            code: 0x45,
            jt: 6,
            jf: 0,
            k: 0x00001fff,
        },
        libc::sock_filter {
            code: 0xb1,
            jt: 0,
            jf: 0,
            k: 0x0000000e,
        },
        libc::sock_filter {
            code: 0x48,
            jt: 0,
            jf: 0,
            k: 0x0000000e,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 2,
            jf: 0,
            k: 0x00000043,
        },
        libc::sock_filter {
            code: 0x48,
            jt: 0,
            jf: 0,
            k: 0x00000010,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: 0x00000043,
        },
        libc::sock_filter {
            code: 0x6,
            jt: 0,
            jf: 0,
            k: 0x00040000,
        },
        libc::sock_filter {
            code: 0x6,
            jt: 0,
            jf: 0,
            k: 0x00000000,
        },
    ];

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
