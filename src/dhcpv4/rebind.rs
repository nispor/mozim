// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use super::{
    time::MIN_REBIND_RENEW_WAIT_TIME, DhcpV4Message, DhcpV4MessageType,
    DhcpV4Socket,
};
use crate::{DhcpError, DhcpV4Client, DhcpV4State, ErrorKind};

impl DhcpV4Client {
    // Broadcast to all DHCP servers requesting lease extension with ciaddr.
    pub(crate) async fn rebind(&mut self) -> Result<(), DhcpError> {
        loop {
            let max_wait_time = self.rebind_max_wait_time()?;

            if max_wait_time.is_zero() {
                log::debug!("DHCP lease expired, entering init_reboot state");
                self.lease = None;
                self.state = DhcpV4State::InitReboot;
                return Ok(());
            }

            match tokio::time::timeout(max_wait_time, self._rebind()).await {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(e)) => {
                    if max_wait_time < MIN_REBIND_RENEW_WAIT_TIME {
                        log::info!(
                            "Rebind fails with error {e}, will fallback to
                            init_reboot state after {} seconds",
                            max_wait_time.as_secs()
                        );
                    } else {
                        log::info!(
                            "Retrying on error {e} after {} seconds",
                            max_wait_time.as_secs()
                        );
                    }
                    // We assume the failure is instant, so will not consider
                    // the time elapsed.
                    tokio::time::sleep(max_wait_time).await;
                }
                Err(_) => {
                    if max_wait_time < MIN_REBIND_RENEW_WAIT_TIME {
                        log::info!(
                            "Timeout on rebinding, fallback to init_reboot \
                             state",
                        );
                    } else {
                        log::info!(
                            "Timeout({}s) on waiting DHCP server DHCPACK \
                             reply for DHCPREQUEST rebind, retrying",
                            max_wait_time.as_secs(),
                        );
                    }
                    self.retry_count += 1;
                }
            }
        }
    }

    // RFC 2131, section 4.4.5 Reacquisition and expiration
    //      In both RENEWING and REBINDING states, if the client receives no
    //      response to its DHCPREQUEST message, the client SHOULD wait
    //      one-half of the remaining time until T2 (in RENEWING state) and
    //      one-half of the remaining lease time (in REBINDING state), down to
    //      a minimum of 60 seconds, before retransmitting the DHCPREQUEST
    //      message.
    //
    // In practice, if there is less than 60 seconds till lease expired, we
    // should only wait the lease remaining time.
    //
    // Return `Duration::ZERO` if lease expired.
    fn rebind_max_wait_time(&self) -> Result<Duration, DhcpError> {
        if let Some(lease) = self.lease_timer.as_ref() {
            let remains = lease.remains()?;
            if remains.is_zero() {
                Ok(Duration::ZERO)
            } else {
                Ok(std::cmp::min(
                    remains,
                    std::cmp::max(remains / 2, MIN_REBIND_RENEW_WAIT_TIME),
                ))
            }
        } else {
            Err(DhcpError::new(
                ErrorKind::Bug,
                format!(
                    "gen_rebind_max_wait_time() invoked without lease timer: \
                     {self:?}"
                ),
            ))
        }
    }

    async fn _rebind(&mut self) -> Result<(), DhcpError> {
        let lease = match self.lease.as_ref() {
            Some(l) => l,
            None => {
                log::error!(
                    "BUG: Got empty lease but in DhcpV4State::Rebinding, \
                     rollback to DhcpV4State::InitReboot"
                );
                self.state = DhcpV4State::InitReboot;
                return Ok(());
            }
        };
        let mut dhcp_msg = DhcpV4Message::new(
            &self.config,
            DhcpV4MessageType::Request,
            self.xid,
        );
        dhcp_msg.load_lease(lease.clone());
        dhcp_msg.renew_or_rebind(true);
        let xid = self.xid;
        let raw_socket = self.get_raw_socket_or_init().await?;

        log::debug!("Sending broadcast DHCPREQUEST for rebind");

        raw_socket
            .send(&dhcp_msg.to_eth_packet_broadcast()?)
            .await?;
        log::debug!("Waiting server reply with DHCPACK");
        loop {
            match raw_socket
                .recv_dhcp_lease(DhcpV4MessageType::Ack, xid)
                .await
            {
                Ok(Some(l)) => {
                    self.done(l)?;
                    return Ok(());
                }
                Ok(None) => (),
                Err(e) => {
                    log::info!("Ignoring invalid DHCP package: {e}");
                }
            };
        }
    }
}
