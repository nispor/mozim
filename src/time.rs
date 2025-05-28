// SPDX-License-Identifier: Apache-2.0

use std::os::fd::AsFd;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;

use nix::sys::time::TimeSpec;
use nix::sys::timerfd::{
    ClockId::CLOCK_BOOTTIME, Expiration, TimerFd, TimerFlags, TimerSetTimeFlags,
};

use crate::{DhcpError, ErrorKind};

#[derive(Debug)]
pub(crate) struct DhcpTimerFd {
    pub(crate) fd: TimerFd,
}

impl AsRawFd for DhcpTimerFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_fd().as_raw_fd()
    }
}

impl DhcpTimerFd {
    pub(crate) fn new(time: Duration) -> Result<Self, DhcpError> {
        let fd =
            TimerFd::new(CLOCK_BOOTTIME, TimerFlags::empty()).map_err(|e| {
                let e = DhcpError::new(
                    ErrorKind::Bug,
                    format!("Failed to create timerfd {e}"),
                );
                log::error!("{e}");
                e
            })?;
        fd.set(
            Expiration::OneShot(TimeSpec::from_duration(time)),
            TimerSetTimeFlags::empty(),
        )
        .map_err(|e| {
            let e = DhcpError::new(
                ErrorKind::Bug,
                format!("Failed to set timerfd {e}"),
            );
            log::error!("{e}");
            e
        })?;
        log::debug!(
            "TimerFd created {:?} with {} milliseconds",
            fd,
            time.as_millis()
        );
        Ok(Self { fd })
    }
}
