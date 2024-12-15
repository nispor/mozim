// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::os::fd::BorrowedFd;
use std::os::unix::io::{AsRawFd, RawFd};

use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags};

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
                    format!("Got unexpected event ID {v}"),
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
    pub(crate) epoll: DhcpEpoll,
}

impl Drop for DhcpEventPool {
    fn drop(&mut self) {
        self.remove_all_event();
    }
}

impl DhcpEventPool {
    pub(crate) fn remove_all_event(&mut self) {
        for (_, timer_fd) in self.timer_fds.drain() {
            self.epoll.del_fd(timer_fd.as_raw_fd()).ok();
        }
        for (_, fd) in self.socket_fds.drain() {
            self.epoll.del_fd(fd).ok();
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
            self.epoll.del_fd(timer_fd.as_raw_fd())?;
        }
        Ok(())
    }

    pub(crate) fn poll(
        &self,
        wait_time: u32,
    ) -> Result<Vec<DhcpV4Event>, DhcpError> {
        match isize::try_from(wait_time) {
            Ok(i) => self.epoll.poll(i),
            Err(_) => Err(DhcpError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Invalid timeout, should be in the range of \
                            0 - {}",
                    isize::MAX
                ),
            )),
        }
    }
}

#[derive(Debug)]
pub(crate) struct DhcpEpoll {
    fd: Epoll,
}

impl AsRawFd for DhcpEpoll {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.0.as_raw_fd()
    }
}

impl DhcpEpoll {
    fn new() -> Result<Self, DhcpError> {
        Ok(Self {
            fd: Epoll::new(EpollCreateFlags::empty()).map_err(|e| {
                let e = DhcpError::new(
                    ErrorKind::Bug,
                    format!("Failed to create Epoll: {e}"),
                );
                log::error!("{e}");
                e
            })?,
        })
    }

    fn add_fd(&self, fd: RawFd, event: DhcpV4Event) -> Result<(), DhcpError> {
        let fd = unsafe { BorrowedFd::borrow_raw(fd) };
        log::debug!(
            "Adding fd {} to Epoll {}, event {}",
            fd.as_raw_fd(),
            self.fd.0.as_raw_fd(),
            event
        );
        let event = EpollEvent::new(EpollFlags::EPOLLIN, event as u64);
        self.fd.add(fd, event).map_err(|e| {
            let e = DhcpError::new(
                ErrorKind::Bug,
                format!(
                    "Failed to add fd {} with event {} to epoll {}: {e}",
                    fd.as_raw_fd(),
                    event.data(),
                    self.fd.0.as_raw_fd()
                ),
            );
            log::error!("{}", e);
            e
        })
    }

    fn del_fd(&self, fd: RawFd) -> Result<(), DhcpError> {
        let fd = unsafe { BorrowedFd::borrow_raw(fd) };
        log::debug!(
            "Removing fd {} from Epoll {}",
            fd.as_raw_fd(),
            self.fd.0.as_raw_fd()
        );
        self.fd.delete(fd).map_err(|e| {
            let e = DhcpError::new(
                ErrorKind::Bug,
                format!(
                    "Failed to delete fd {} from epoll {}: {e}",
                    fd.as_raw_fd(),
                    self.fd.0.as_raw_fd(),
                ),
            );
            log::error!("{}", e);
            e
        })
    }

    fn poll(&self, wait_time: isize) -> Result<Vec<DhcpV4Event>, DhcpError> {
        let mut events: [EpollEvent; EVENT_BUFFER_COUNT] =
            [EpollEvent::empty(); EVENT_BUFFER_COUNT];

        loop {
            match self.fd.wait(&mut events, 1000 * wait_time as u16) {
                Ok(c) => {
                    let mut ret = Vec::new();
                    for i in &events[..c] {
                        ret.push(DhcpV4Event::try_from(i.data())?);
                    }
                    return Ok(ret);
                }
                Err(e) => match e {
                    nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN => {
                        // retry
                        continue;
                    }
                    _ => {
                        let e = DhcpError::new(
                            ErrorKind::Bug,
                            format!("Failed on epoll_wait(): {e}"),
                        );
                        return Err(e);
                    }
                },
            }
        }
    }
}
