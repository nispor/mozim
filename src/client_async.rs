// SPDX-License-Identifier: Apache-2.0

use std::os::fd::BorrowedFd;
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures::{
    task::{Context, Poll, Waker},
    Stream,
};
use nix::poll::{PollFd, PollFlags};

use crate::{
    DhcpError, DhcpV4Client, DhcpV4Config, DhcpV4Lease, DhcpV6Client,
    DhcpV6Config, DhcpV6Lease, ErrorKind,
};

const POLL_TIMEOUT: u16 = 1000; // milliseconds

#[derive(Debug)]
struct ShareState {
    waker: Option<Waker>,
}

#[derive(Debug)]
pub struct DhcpV4ClientAsync {
    client: DhcpV4Client,
    share_state: Arc<Mutex<ShareState>>,
}

impl Stream for DhcpV4ClientAsync {
    type Item = Result<DhcpV4Lease, DhcpError>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        // Poll without wait
        match self.client.poll(0) {
            Ok(events) => {
                for event in events {
                    match self.client.process(event) {
                        Ok(Some(lease)) => {
                            return Poll::Ready(Some(Ok(lease)));
                        }
                        Ok(None) => (),
                        Err(e) => {
                            return Poll::Ready(Some(Err(e)));
                        }
                    }
                }
            }
            Err(e) => {
                log::error!("DHCP client poll error: {e}");
                return Poll::Ready(Some(Err(e)));
            }
        }

        let mut share_state = match self.share_state.lock() {
            Ok(s) => s,
            Err(e) => {
                return Poll::Ready(Some(Err(DhcpError::new(
                    ErrorKind::Bug,
                    format!(
                        "BUG: DhcpV4ClientAsync::poll_next() \
                        Failed to acquire lock on share_state {e}",
                    ),
                ))));
            }
        };
        if share_state.waker.is_none() {
            share_state.waker = Some(cx.waker().clone());
            drop(share_state);
            let fd = self.client.as_raw_fd();
            let share_state = self.share_state.clone();
            std::thread::spawn(move || poll_thread(fd, share_state));
        } else {
            share_state.waker = Some(cx.waker().clone());
            drop(share_state);
        }

        Poll::Pending
    }
}

impl DhcpV4ClientAsync {
    pub fn init(
        config: DhcpV4Config,
        lease: Option<DhcpV4Lease>,
    ) -> Result<Self, DhcpError> {
        Ok(Self {
            client: DhcpV4Client::init(config, lease)?,
            share_state: Arc::new(Mutex::new(ShareState { waker: None })),
        })
    }
}

impl std::ops::Drop for DhcpV4ClientAsync {
    fn drop(&mut self) {
        if let Ok(mut s) = self.share_state.lock() {
            // Signal `poll_thread()` to quit
            s.waker = None;
        }
    }
}

// This function will be invoked in a thread to notify the async executor
// via `Waker::wake()`. Will quit when `poll()` failed (except EAGAIN).
fn poll_thread(fd: RawFd, share_state: Arc<Mutex<ShareState>>) {
    let fd = unsafe { BorrowedFd::borrow_raw(fd) };
    let mut poll_fds = [PollFd::new(
        fd,
        PollFlags::POLLIN
            | PollFlags::POLLOUT
            | PollFlags::POLLHUP
            | PollFlags::POLLERR,
    )];
    loop {
        if share_state.lock().map(|s| s.waker.is_none()).ok() == Some(true) {
            std::thread::sleep(std::time::Duration::from_millis(
                POLL_TIMEOUT as u64,
            ));
        } else {
            match nix::poll::poll(&mut poll_fds, POLL_TIMEOUT) {
                // Timeout, let's check whether waker is None(DHCP client quit);
                Ok(0) => {
                    continue;
                }
                Ok(_) => match share_state.lock() {
                    Ok(mut s) => {
                        if let Some(waker) = s.waker.take() {
                            log::debug!("poll_thread got event");
                            waker.wake();
                        } else {
                            log::debug!(
                                "poll_thread got event but Waker is None"
                            );
                        }
                    }
                    Err(e) => {
                        log::error!(
                            "BUG: poll_thread() Failed to acquire lock: {e}"
                        );
                        return;
                    }
                },
                Err(e) => {
                    if e == nix::errno::Errno::EAGAIN {
                        continue;
                    } else {
                        log::error!(
                            "BUG: poll_thread() got error from poll(): {e}"
                        );
                        return;
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct DhcpV6ClientAsync {
    client: DhcpV6Client,
    share_state: Arc<Mutex<ShareState>>,
}

impl Stream for DhcpV6ClientAsync {
    type Item = Result<DhcpV6Lease, DhcpError>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        // Poll without wait
        match self.client.poll(0) {
            Ok(events) => {
                for event in events {
                    match self.client.process(event) {
                        Ok(Some(lease)) => {
                            return Poll::Ready(Some(Ok(lease)));
                        }
                        Ok(None) => (),
                        Err(e) => {
                            return Poll::Ready(Some(Err(e)));
                        }
                    }
                }
            }
            Err(e) => {
                log::error!("DHCP client poll error: {e}");
                return Poll::Ready(Some(Err(e)));
            }
        }

        let mut share_state = match self.share_state.lock() {
            Ok(s) => s,
            Err(e) => {
                return Poll::Ready(Some(Err(DhcpError::new(
                    ErrorKind::Bug,
                    format!(
                        "BUG: DhcpV6ClientAsync::poll_next() \
                        Failed to acquire lock on share_state {e}",
                    ),
                ))));
            }
        };
        if share_state.waker.is_none() {
            share_state.waker = Some(cx.waker().clone());
            drop(share_state);
            let fd = self.client.as_raw_fd();
            let share_state = self.share_state.clone();
            std::thread::spawn(move || poll_thread(fd, share_state));
        } else {
            share_state.waker = Some(cx.waker().clone());
            drop(share_state);
        }

        Poll::Pending
    }
}

impl DhcpV6ClientAsync {
    pub fn init(
        config: DhcpV6Config,
        lease: Option<DhcpV6Lease>,
    ) -> Result<Self, DhcpError> {
        Ok(Self {
            client: DhcpV6Client::init(config, lease)?,
            share_state: Arc::new(Mutex::new(ShareState { waker: None })),
        })
    }
}

impl std::ops::Drop for DhcpV6ClientAsync {
    fn drop(&mut self) {
        if let Ok(mut s) = self.share_state.lock() {
            // Signal `poll_thread()` to quit
            s.waker = None;
        }
    }
}
