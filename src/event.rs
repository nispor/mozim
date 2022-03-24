use std::convert::TryFrom;
use std::os::unix::io::RawFd;

use nix::sys::epoll::{
    epoll_create, epoll_ctl, epoll_wait, EpollEvent, EpollFlags, EpollOp,
};

use crate::{DhcpError, ErrorKind};

const EVENT_BUFFER_COUNT: usize = 64;
const POLL_TIMEOUT: isize = 1000;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum DhcpV4Event {
    RawPackageIn = 1,
    DiscoveryTimeout,
    RequestTimeout,
    Timeout,
    DiscoveryRetry,
    Renew,
    RenewRetry,
    Rebind,
    RebindRetry,
}

impl TryFrom<u64> for DhcpV4Event {
    type Error = DhcpError;
    fn try_from(v: u64) -> Result<Self, DhcpError> {
        match v {
            x if x == Self::RawPackageIn as u64 => Ok(Self::RawPackageIn),
            x if x == Self::DiscoveryTimeout as u64 => {
                Ok(Self::DiscoveryTimeout)
            }
            x if x == Self::RequestTimeout as u64 => Ok(Self::RequestTimeout),
            x if x == Self::Timeout as u64 => Ok(Self::Timeout),
            x if x == Self::DiscoveryRetry as u64 => Ok(Self::DiscoveryRetry),
            x if x == Self::Renew as u64 => Ok(Self::Renew),
            x if x == Self::RenewRetry as u64 => Ok(Self::RenewRetry),
            x if x == Self::Rebind as u64 => Ok(Self::Rebind),
            x if x == Self::RebindRetry as u64 => Ok(Self::RebindRetry),
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

#[derive(Debug, PartialEq, Clone, Default)]
pub(crate) struct DhcpEpoll {
    fd: RawFd,
}

impl DhcpEpoll {
    pub(crate) fn new() -> Result<Self, DhcpError> {
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

    pub(crate) fn add_fd(
        &self,
        fd: RawFd,
        event: DhcpV4Event,
    ) -> Result<(), DhcpError> {
        let event = EpollEvent::new(EpollFlags::EPOLLIN, event as u64);
        log::debug!("Adding fd {} to Epoll {}, event {:?}", fd, self.fd, event);
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

    pub(crate) fn del_fd(
        &self,
        fd: RawFd,
        event: DhcpV4Event,
    ) -> Result<(), DhcpError> {
        let event = EpollEvent::new(EpollFlags::EPOLLIN, event as u64);
        log::debug!(
            "Removing fd {} to Epoll {}, event {:?}",
            fd,
            self.fd,
            event
        );
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

    pub(crate) fn poll(
        &self,
        wait_time: isize,
    ) -> Result<Vec<DhcpV4Event>, DhcpError> {
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
