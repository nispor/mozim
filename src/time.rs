use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::time::Duration;

use nix::sys::time::{TimeSpec, TimeValLike};
use nix::sys::timerfd::{
    ClockId::CLOCK_BOOTTIME, Expiration, TimerFd, TimerFlags, TimerSetTimeFlags,
};
use rand::Rng;

use crate::{
    event::{DhcpEpoll, DhcpV4Event},
    DhcpError, ErrorKind,
};

#[derive(Debug)]
pub(crate) struct DhcpTimerFds {
    timer_fds: HashMap<DhcpV4Event, DhcpTimerFd>,
}

impl Default for DhcpTimerFds {
    fn default() -> Self {
        Self {
            timer_fds: HashMap::new(),
        }
    }
}

impl DhcpTimerFds {
    pub(crate) fn add_event(
        &mut self,
        epoll: &DhcpEpoll,
        event: DhcpV4Event,
        timeout: u32,
    ) -> Result<(), DhcpError> {
        let timer_fd = DhcpTimerFd::new(timeout)?;
        epoll.add_fd(timer_fd.as_raw_fd(), event)?;
        self.timer_fds.insert(event, timer_fd);
        Ok(())
    }

    pub(crate) fn del_event(
        &mut self,
        epoll: &DhcpEpoll,
        event: DhcpV4Event,
    ) -> Result<(), DhcpError> {
        if let Some(timer_fd) = self.timer_fds.remove(&event) {
            epoll.del_fd(timer_fd.as_raw_fd(), event)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct DhcpTimerFd {
    pub(crate) fd: TimerFd,
}

impl std::os::unix::io::AsRawFd for DhcpTimerFd {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.fd.as_raw_fd()
    }
}

impl DhcpTimerFd {
    pub(crate) fn new(time: u32) -> Result<Self, DhcpError> {
        let fd =
            TimerFd::new(CLOCK_BOOTTIME, TimerFlags::empty()).map_err(|e| {
                let e = DhcpError::new(
                    ErrorKind::Bug,
                    format!("Failed to create timerfd {}", e),
                );
                log::error!("{}", e);
                e
            })?;
        fd.set(
            Expiration::OneShot(TimeSpec::seconds(time.into())),
            TimerSetTimeFlags::empty(),
        )
        .map_err(|e| {
            let e = DhcpError::new(
                ErrorKind::Bug,
                format!("Failed to set timerfd {}", e),
            );
            log::error!("{}", e);
            e
        })?;
        log::debug!("TimerFd created {:?} with {} seconds", fd, time);
        Ok(Self { fd })
    }
}

// The boot time is holding CLOCK_BOOTTIME which also includes any time that the
// system is suspended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct BootTime {
    pub sec: i64,
    pub nsec: i64,
}

impl BootTime {
    pub(crate) fn sanitize(&self) -> BootTime {
        if self.nsec > 1_000_000_000 || self.nsec < 0 {
            let mut add = self.nsec / 1_000_000_000;
            if self.nsec < 0 {
                add -= 1;
            }
            BootTime {
                sec: self.sec + add,
                nsec: self.nsec - add * 1_000_000_000,
            }
        } else {
            *self
        }
    }

    pub(crate) fn now() -> Self {
        let mut tp = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe {
            libc::clock_gettime(
                libc::CLOCK_BOOTTIME,
                &mut tp as *mut libc::timespec,
            );
        }
        Self {
            sec: tp.tv_sec,
            nsec: tp.tv_nsec,
        }
    }

    pub(crate) fn new(sec: i64, nsec: i64) -> Self {
        Self { sec, nsec }
    }

    pub(crate) fn elapsed(&self) -> Result<std::time::Duration, DhcpError> {
        let diff: BootTime = Self::now() - *self;
        if diff.sec < 0 || diff.nsec < 0 {
            let e = DhcpError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Specified time {:?} is in the future, now {:?}, diff {:?}",
                    self,
                    Self::now(),
                    diff,
                ),
            );
            log::error!("{}", e);
            Err(e)
        } else {
            Ok(std::time::Duration::new(diff.sec as u64, diff.nsec as u32))
        }
    }
}

impl std::ops::Sub<BootTime> for BootTime {
    type Output = BootTime;
    fn sub(self, other: BootTime) -> BootTime {
        BootTime {
            sec: self.sec - other.sec,
            nsec: self.nsec - other.nsec,
        }
        .sanitize()
    }
}

impl std::ops::Add<BootTime> for BootTime {
    type Output = BootTime;
    fn add(self, other: BootTime) -> BootTime {
        BootTime {
            sec: self.sec + other.sec,
            nsec: self.nsec + other.nsec,
        }
        .sanitize()
    }
}

impl std::ops::Div<u32> for BootTime {
    type Output = BootTime;
    fn div(self, other: u32) -> BootTime {
        BootTime {
            sec: self.sec / (other as i64),
            nsec: (self.nsec + 1_000_000_000 * (self.sec % (other as i64)))
                / (other as i64),
        }
    }
}

// RFC 2131, section 4.1 "Constructing and sending DHCP messages" has
// retransmission guideline.
// It should be starting with 4 seconds and double of previous delay, up to 64
// seconds. Delay should be randomized from range -1 to 1;
pub(crate) fn gen_dhcp_request_delay(retry_count: u32) -> u32 {
    let mut base = 2u64.pow(retry_count + 2) - 1;
    if base > 62 {
        base = 62;
    }
    let ms: u64 = rand::thread_rng().gen_range(0..2000);
    (Duration::from_secs(base) + Duration::from_millis(ms))
        .as_secs()
        .try_into()
        .unwrap_or(u32::MAX)
}
