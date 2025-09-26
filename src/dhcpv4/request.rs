// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use super::{
    msg::{DhcpV4Message, DhcpV4MessageType},
    DhcpV4Socket, DhcpV4State,
};
use crate::{DhcpError, DhcpV4Client};

impl DhcpV4Client {
    pub(crate) async fn request(&mut self) -> Result<(), DhcpError> {
        loop {
            let max_wait_time = self.requset_max_wait_time();

            match tokio::time::timeout(max_wait_time, self._request()).await {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(e)) => {
                    log::info!(
                        "Retrying on error {e} after {} seconds",
                        max_wait_time.as_secs()
                    );
                    // We assume the failure is instant, so will not consider
                    // the time elapsed.
                    tokio::time::sleep(max_wait_time).await;
                }
                Err(_) => {
                    log::info!(
                        "Timeout({}s) on waiting DHCP server DHCPACK reply \
                         for DHCPREQUEST, retrying",
                        max_wait_time.as_secs(),
                    );
                    self.retry_count += 1;
                }
            }
        }
    }

    fn requset_max_wait_time(&self) -> Duration {
        self.discovery_max_wait_time()
    }

    async fn _request(&mut self) -> Result<(), DhcpError> {
        let lease = match self.pending_lease.take() {
            Some(l) => l,
            None => {
                log::error!(
                    "BUG: Got empty lease but in DhcpV4State::Selecting, \
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
        let xid = self.xid;
        let raw_socket = self.get_raw_socket_or_init().await?;

        log::debug!("Sending DHCPREQUEST");

        raw_socket
            .send(&dhcp_msg.to_eth_packet_broadcast()?)
            .await?;

        log::debug!("Waiting DHCP server reply with DHCPACK");
        // Make sure we wait all reply from DHCP server instead of
        // failing on first DHCP invalid reply
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
