// SPDX-License-Identifier: Apache-2.0

use std::{io, os::fd::OwnedFd};

use tokio::io::unix::AsyncFd;

pub(crate) fn register_owned_fd(fd: OwnedFd) -> io::Result<AsyncFd<OwnedFd>> {
    // SAFETY: `fd` owns an open file descriptor and keeps it open and
    // unchanged for the lifetime of the `AsyncFd`.
    unsafe { AsyncFd::register(fd) }.map_err(io::Error::from)
}
