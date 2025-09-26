// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use super::{
    msg::{DhcpV6Message, DhcpV6MessageType},
    time::gen_retransmit_time,
    DhcpV6State,
};
use crate::{DhcpError, DhcpV6Client, ErrorKind};

// RFC 8415 section 7.6 Transmission and Retransmission Parameters
const REB_TIMEOUT: Duration = Duration::from_secs(10);
const REB_MAX_RT: Duration = Duration::from_secs(600);

impl DhcpV6Client {
    fn gen_rebind_wait_time(&self) -> Result<Duration, DhcpError> {
        let valid_sec = if let Some(valid_sec) =
            self.lease.as_ref().map(|l| l.valid_time_sec)
        {
            valid_sec
        } else {
            return Err(DhcpError::new(
                ErrorKind::Bug,
                format!("In Rebind state without lease: {self:?}"),
            ));
        };

        if let Some(valid) = self.valid_timer.as_ref() {
            let remains = valid.remains()?;
            Ok(std::cmp::min(
                remains,
                gen_retransmit_time(
                    self.trans_begin_time,
                    self.retransmit_count,
                    self.retransmit_timeout,
                    REB_TIMEOUT,
                    REB_MAX_RT,
                    0,
                    Duration::from_secs(valid_sec.into()),
                )
                .unwrap_or(Duration::new(0, 0)),
            ))
        } else {
            Err(DhcpError::new(
                ErrorKind::Bug,
                format!("In Rebind state without lease valid timer: {self:?}"),
            ))
        }
    }

    pub(crate) async fn rebind(&mut self) -> Result<(), DhcpError> {
        if self.retransmit_count == 0 {
            self.trans_begin_time = Instant::now();
        }

        loop {
            self.retransmit_timeout = self.gen_rebind_wait_time()?;

            if self.retransmit_timeout.is_zero() {
                log::info!(
                    "Exceeded lease valid time for Rebind stage, move to \
                     Solicit stage"
                );
                self.reset_retransmit_counters();
                self.lease = None;
                self.state = DhcpV6State::Solicit;
                return Ok(());
            };

            match tokio::time::timeout(self.retransmit_timeout, self._rebind())
                .await
            {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(e)) => {
                    log::info!(
                        "Retrying on error {e} after {} seconds",
                        self.retransmit_timeout.as_secs()
                    );
                    // We assume the failure is instant, so will not consider
                    // the time elapsed.
                    tokio::time::sleep(self.retransmit_timeout).await;
                }
                Err(_) => {
                    log::info!(
                        "Timeout({}s) on waiting DHCP server Reply for \
                         Rebind, retrying",
                        self.retransmit_timeout.as_secs(),
                    );
                    self.retransmit_count += 1;
                }
            }
        }
    }

    async fn _rebind(&mut self) -> Result<(), DhcpError> {
        let lease = if let Some(l) = self.lease.as_ref() {
            l
        } else {
            return Err(DhcpError::new(
                ErrorKind::Bug,
                format!("In Rebind state without lease: {self:?}"),
            ));
        };
        let mut dhcp_packet = DhcpV6Message::new(
            self.config.mode,
            self.config.duid.clone(),
            DhcpV6MessageType::REBIND,
            self.xid,
        );
        let xid = self.xid;
        dhcp_packet.load_lease(lease.clone())?;

        dhcp_packet.add_elapsed_time(self.trans_begin_time);

        let udp_socket = self.get_udp_socket_or_init().await?;

        log::debug!("Sending Rebind");
        log::trace!("Sending Rebind {dhcp_packet:?}");

        udp_socket
            .send_multicast(&dhcp_packet.to_dhcp_packet()?)
            .await?;
        log::debug!("Waiting server reply with Reply");
        // Make sure we wait all reply from DHCP server instead of
        // failing on first DHCP invalid reply
        loop {
            match udp_socket
                .recv_dhcp_lease(DhcpV6MessageType::REPLY, xid)
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
