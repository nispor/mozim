use std::collections::HashMap;
use std::convert::TryFrom;
use std::os::unix::io::{AsRawFd, RawFd};

use nix::sys::epoll::{
    epoll_create, epoll_ctl, epoll_wait, EpollEvent, EpollFlags, EpollOp,
};

use crate::{time::DhcpTimerFd, DhcpError, ErrorKind};

const EVENT_BUFFER_COUNT: usize = 64;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum DhcpV4Event {
    RawPackageIn = 1,
    UdpPackageIn,
    DiscoveryTimeout,
    RequestTimeout,
    Timeout,
    Renew,
    RenewRetry,
    Rebind,
    RebindRetry,
    LeaseExpired,
}

impl TryFrom<u64> for DhcpV4Event {
    type Error = DhcpError;
    fn try_from(v: u64) -> Result<Self, DhcpError> {
        match v {
            x if x == Self::RawPackageIn as u64 => Ok(Self::RawPackageIn),
            x if x == Self::UdpPackageIn as u64 => Ok(Self::UdpPackageIn),
            x if x == Self::DiscoveryTimeout as u64 => {
                Ok(Self::DiscoveryTimeout)
            }
            x if x == Self::RequestTimeout as u64 => Ok(Self::RequestTimeout),
            x if x == Self::Timeout as u64 => Ok(Self::Timeout),
            x if x == Self::Renew as u64 => Ok(Self::Renew),
            x if x == Self::RenewRetry as u64 => Ok(Self::RenewRetry),
            x if x == Self::Rebind as u64 => Ok(Self::Rebind),
            x if x == Self::RebindRetry as u64 => Ok(Self::RebindRetry),
            x if x == Self::LeaseExpired as u64 => Ok(Self::LeaseExpired),
            _ => {
                let e = DhcpError::new(
                    ErrorKind::Bug,
                    format!("Got unexpected event ID {}", v),
                );
                log::error!("{}", e);
                Err(e)
            }
        }
    }
}

impl std::fmt::Display for DhcpV4Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::RawPackageIn => "RawPackageIn",
                Self::UdpPackageIn => "UdpPackageIn",
                Self::DiscoveryTimeout => "DiscoveryTimeout",
                Self::RequestTimeout => "RequestTimeout",
                Self::Timeout => "Timeout",
                Self::Renew => "Renew",
                Self::RenewRetry => "RenewRetry",
                Self::Rebind => "Rebind",
                Self::RebindRetry => "RebindRetry",
                Self::LeaseExpired => "LeaseExpired",
            }
        )
    }
}

#[derive(Debug)]
pub(crate) struct DhcpEventPool {
    timer_fds: HashMap<DhcpV4Event, DhcpTimerFd>,
    socket_fds: HashMap<DhcpV4Event, RawFd>,
    epoll: DhcpEpoll,
}

impl Drop for DhcpEventPool {
    fn drop(&mut self) {
        self.remove_all_event();
        if self.epoll.fd >= 0 {
            unsafe {
                libc::close(self.epoll.fd as libc::c_int);
            }
        }
    }
}

impl DhcpEventPool {
    pub(crate) fn remove_all_event(&mut self) {
        for (event, timer_fd) in self.timer_fds.drain() {
            self.epoll.del_fd(timer_fd.as_raw_fd(), event).ok();
        }
        for (event, fd) in self.socket_fds.drain() {
            self.epoll.del_fd(fd, event).ok();
        }
    }

    pub(crate) fn new() -> Result<Self, DhcpError> {
        Ok(Self {
            timer_fds: HashMap::new(),
            socket_fds: HashMap::new(),
            epoll: DhcpEpoll::new()?,
        })
    }

    pub(crate) fn add_socket(
        &mut self,
        fd: RawFd,
        event: DhcpV4Event,
    ) -> Result<(), DhcpError> {
        log::debug!("Adding socket {} with event {} to event pool", fd, event);
        self.socket_fds.insert(event, fd);
        self.epoll.add_fd(fd, event)
    }

    pub(crate) fn add_timer(
        &mut self,
        timeout: u32,
        event: DhcpV4Event,
    ) -> Result<(), DhcpError> {
        log::debug!(
            "Adding timer {} seconds with event {} to event pool",
            timeout,
            event
        );
        let timer_fd = DhcpTimerFd::new(timeout)?;
        self.epoll.add_fd(timer_fd.as_raw_fd(), event)?;
        self.timer_fds.insert(event, timer_fd);
        Ok(())
    }

    pub(crate) fn del_timer(
        &mut self,
        event: DhcpV4Event,
    ) -> Result<(), DhcpError> {
        if let Some(timer_fd) = self.timer_fds.remove(&event) {
            self.epoll.del_fd(timer_fd.as_raw_fd(), event)?;
        }
        Ok(())
    }

    pub(crate) fn poll(
        &self,
        wait_time: isize,
    ) -> Result<Vec<DhcpV4Event>, DhcpError> {
        self.epoll.poll(wait_time)
    }
}

#[derive(Debug)]
struct DhcpEpoll {
    fd: RawFd,
}

impl DhcpEpoll {
    fn new() -> Result<Self, DhcpError> {
        Ok(Self {
            fd: epoll_create().map_err(|e| {
                let e = DhcpError::new(
                    ErrorKind::Bug,
                    format!("Failed to epoll_create(): {}", e),
                );
                log::error!("{}", e);
                e
            })?,
        })
    }

    fn add_fd(&self, fd: RawFd, event: DhcpV4Event) -> Result<(), DhcpError> {
        log::debug!("Adding fd {} to Epoll {}, event {}", fd, self.fd, event);
        let event = EpollEvent::new(EpollFlags::EPOLLIN, event as u64);
        epoll_ctl(self.fd, EpollOp::EpollCtlAdd, fd, &mut Some(event)).map_err(
            |e| {
                let e = DhcpError::new(
                    ErrorKind::Bug,
                    format!(
                        "Failed to epoll_ctl({}, {:?}, {}, {:?}): {}",
                        self.fd,
                        EpollOp::EpollCtlAdd,
                        fd,
                        event,
                        e
                    ),
                );
                log::error!("{}", e);
                e
            },
        )
    }

    fn del_fd(&self, fd: RawFd, event: DhcpV4Event) -> Result<(), DhcpError> {
        log::debug!(
            "Removing fd {} from Epoll {}, event {}",
            fd,
            self.fd,
            event
        );
        let event = EpollEvent::new(EpollFlags::EPOLLIN, event as u64);
        epoll_ctl(self.fd, EpollOp::EpollCtlDel, fd, &mut Some(event)).map_err(
            |e| {
                let e = DhcpError::new(
                    ErrorKind::Bug,
                    format!(
                        "Failed to epoll_ctl({}, {:?}, {}, {:?}): {}",
                        self.fd,
                        EpollOp::EpollCtlDel,
                        fd,
                        event,
                        e
                    ),
                );
                log::error!("{}", e);
                e
            },
        )
    }

    fn poll(&self, wait_time: isize) -> Result<Vec<DhcpV4Event>, DhcpError> {
        let mut events: [EpollEvent; EVENT_BUFFER_COUNT] =
            [EpollEvent::empty(); EVENT_BUFFER_COUNT];

        let changed_count = epoll_wait(self.fd, &mut events, 1000 * wait_time)
            .map_err(|e| {
                let e = DhcpError::new(
                    ErrorKind::Bug,
                    format!("Failed on epoll_wait(): {}", e),
                );
                log::error!("{}", e);
                e
            })?;
        let mut ret = Vec::new();
        for i in &events[..changed_count] {
            ret.push(DhcpV4Event::try_from(i.data())?);
        }
        Ok(ret)
    }
}
