// SPDX-License-Identifier: Apache-2.0

use crate::{DhcpError, ErrorKind};

pub(crate) fn enable_promiscuous_mode(
    fd: libc::c_int,
    iface_index: libc::c_int,
) -> Result<(), DhcpError> {
    let mreq = libc::packet_mreq {
        mr_ifindex: iface_index,
        mr_type: libc::PACKET_MR_PROMISC as libc::c_ushort,
        mr_alen: 0,
        mr_address: [0; 8],
    };

    unsafe {
        let rc = libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_ADD_MEMBERSHIP,
            (&mreq as *const libc::packet_mreq) as *const libc::c_void,
            std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
        );
        if rc != 0 {
            return Err(DhcpError::new(
                ErrorKind::Bug,
                format!(
                    "Failed to set socket to promiscuous mode with error: {}",
                    rc
                ),
            ));
        }
    }
    Ok(())
}
