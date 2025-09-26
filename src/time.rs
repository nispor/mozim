// SPDX-License-Identifier: Apache-2.0

use std::{os::fd::OwnedFd, time::Duration};

use nix::sys::{
    time::TimeSpec,
    timerfd::{
        ClockId::CLOCK_BOOTTIME, Expiration, TimerFd, TimerFlags,
        TimerSetTimeFlags,
    },
};
use tokio::io::unix::AsyncFd;

use crate::{DhcpError, ErrorKind};

/// Timer depend on CLOCK_BOOTTIME so it continue ticks when system
/// sleeps/hibernates.
#[derive(Debug)]
pub(crate) struct DhcpTimer {
    pub(crate) end: TimeSpec,
}

impl DhcpTimer {
    pub(crate) fn new(time: Duration) -> Result<Self, DhcpError> {
        let end = boot_time_now()? + TimeSpec::from_duration(time);
        Ok(Self { end })
    }

    pub(crate) async fn wait(&self) -> Result<(), DhcpError> {
        let remains = self.remains()?;
        if !remains.is_zero() {
            let fd = TimerFd::new(CLOCK_BOOTTIME, TimerFlags::TFD_NONBLOCK)
                .map_err(|e| {
                    let e = DhcpError::new(
                        ErrorKind::Bug,
                        format!("Failed to create timerfd {e}"),
                    );
                    log::error!("{e}");
                    e
                })?;
            fd.set(
                Expiration::OneShot(TimeSpec::from_duration(remains)),
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
                "DHCP timer created {:?} with {} seconds {} milliseconds",
                fd,
                remains.as_secs(),
                remains.subsec_millis(),
            );
            let _ = AsyncFd::new(OwnedFd::from(fd))?.readable().await?;
        }
        Ok(())
    }

    pub(crate) fn remains(&self) -> Result<Duration, DhcpError> {
        let now = boot_time_now()?;
        if self.end > now {
            Ok((self.end - now).into())
        } else {
            Ok(Duration::ZERO)
        }
    }
}

fn boot_time_now() -> Result<TimeSpec, DhcpError> {
    nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME).map_err(|e| {
        DhcpError::new(
            ErrorKind::Bug,
            format!("Failed to retrieve CLOCK_BOOTTIME: {e}"),
        )
    })
}
