// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use super::{DhcpV4Message, DhcpV4MessageType, DhcpV4Socket, DhcpV4State};
use crate::{DhcpError, DhcpV4Client};

impl DhcpV4Client {
    pub(crate) async fn discovery(&mut self) -> Result<(), DhcpError> {
        // RFC 2131 4.4.1 Initialization and allocation of network address
        // ```
        // The client begins in INIT state and forms a DHCPDISCOVER message.
        // The client SHOULD wait a random time between one and ten seconds to
        // desynchronize the use of DHCP at startup.
        // ```
        // In practice, 10 seconds is too much. Here we wait at most 200ms.
        if self.retry_count == 0 {
            let wait_time: u64 = rand::random_range(0..200);
            tokio::time::sleep(std::time::Duration::from_millis(wait_time))
                .await;
        }
        loop {
            let max_wait_time = self.discovery_max_wait_time();

            match tokio::time::timeout(max_wait_time, self._discovery()).await {
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
                        "Timeout({}s) on waiting DHCP server DHCPOFFER reply \
                         for DHCPDISCOVER, retrying",
                        max_wait_time.as_secs(),
                    );
                    self.retry_count += 1;
                }
            }
        }
    }

    // RFC 2131, section 4.1 "Constructing and sending DHCP messages":
    //      Clients with clocks that provide resolution granularity of less
    //      than one second may choose a non-integer randomization value.  The
    //      delay before the next retransmission SHOULD be 8 seconds randomized
    //      by the value of a uniform number chosen from the range -1 to +1.
    //      The retransmission delay SHOULD be doubled with subsequent
    //      retransmissions up to a maximum of 64 seconds.
    pub(crate) fn discovery_max_wait_time(&self) -> Duration {
        let mut base = 2u64.pow(self.retry_count + 2) - 1;
        if base > 62 {
            base = 62;
        }
        let ms: u64 = rand::random_range(0..2000);
        Duration::from_secs(base) + Duration::from_millis(ms)
    }

    async fn _discovery(&mut self) -> Result<(), DhcpError> {
        self.state = DhcpV4State::InitReboot;
        self.lease = None;
        let dhcp_msg = DhcpV4Message::new(
            &self.config,
            DhcpV4MessageType::Discovery,
            self.xid,
        );
        let xid = self.xid;
        let raw_socket = self.get_raw_socket_or_init().await?;

        log::debug!("Sending DHCPDISCOVER");

        raw_socket
            .send(&dhcp_msg.to_eth_packet_broadcast()?)
            .await?;
        log::debug!("Waiting server reply with DHCPOFFER");
        // Make sure we wait all reply from DHCP server instead of
        // failing on first DHCP invalid reply
        loop {
            match raw_socket
                .recv_dhcp_lease(DhcpV4MessageType::Offer, xid)
                .await
            {
                Ok(Some(l)) => {
                    // TODO(Gris Ge): It is possible for malicious DHCP server
                    // send out DHCPOFFER and do not ack on follow up
                    // DHCPREQUEST. With current code, user will never get a
                    // valid DHCP lease. Even it might be user's fault on
                    // malicious environment, but we should provide a
                    // way to handle this in the future.
                    self.pending_lease = Some(l);
                    self.state = DhcpV4State::Selecting;
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
