use std::time::Duration;

use rand::Rng;

use crate::{DhcpError, ErrorKind};

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
pub(crate) fn gen_dhcp_request_delay(retry_count: u32) -> Duration {
    let mut base = 2u64.pow(retry_count + 2) - 1;
    if base > 62 {
        base = 62;
    }
    let ms: u64 = rand::thread_rng().gen_range(0..2000);
    Duration::from_secs(base) + Duration::from_millis(ms)
}
