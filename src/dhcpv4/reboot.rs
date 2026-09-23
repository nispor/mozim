// SPDX-License-Identifier: Apache-2.0

use super::{socket::DhcpV4Reply, DhcpV4Message, DhcpV4Socket, DhcpV4State};
use crate::{DhcpError, DhcpV4Client};

// RFC 2131, section 4.1 "Constructing and sending DHCP messages" suggests
// giving up after four retransmissions. If the server neither confirms
// (DHCPACK) nor rejects (DHCPNAK) the cached lease after that many tries, we
// cannot verify the lease, so we fall back to acquiring a fresh one via
// DHCPDISCOVER.
const REBOOT_MAX_RETRY_COUNT: u32 = 4;

impl DhcpV4Client {
    // RFC 2131, section 4.4.2 "Initialization with known network address":
    //      The client begins in INIT-REBOOT state and sends a DHCPREQUEST
    //      message. The client MUST insert its known network address as a
    //      'requested IP address' option in the DHCPREQUEST message. [...]
    //      The client MUST NOT include a 'server identifier' [...]. The client
    //      then broadcasts the DHCPREQUEST on the local hardware broadcast
    //      address.
    //
    // The server confirms the cached lease with a DHCPACK, or rejects it with
    // a DHCPNAK. On DHCPNAK, or when no reply is received after
    // `REBOOT_MAX_RETRY_COUNT` retransmissions, we drop the cached lease and
    // restart the acquisition process from INIT state (DHCPDISCOVER).
    pub(crate) async fn reboot(&mut self) -> Result<(), DhcpError> {
        loop {
            let max_wait_time = self.discovery_max_wait_time();

            match tokio::time::timeout(max_wait_time, self._reboot()).await {
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
                    self.retry_count += 1;
                    if self.retry_count >= REBOOT_MAX_RETRY_COUNT {
                        log::info!(
                            "No DHCPACK/DHCPNAK reply for DHCPREQUEST after \
                             {REBOOT_MAX_RETRY_COUNT} tries, cannot verify \
                             cached lease, falling back to requesting a new \
                             lease"
                        );
                        self.lease = None;
                        self.retry_count = 0;
                        self.state = DhcpV4State::InitReboot;
                        return Ok(());
                    }
                    log::info!(
                        "Timeout({}s) on waiting DHCP server DHCPACK/DHCPNAK \
                         reply for DHCPREQUEST reboot, retrying",
                        max_wait_time.as_secs(),
                    );
                }
            }
        }
    }

    async fn _reboot(&mut self) -> Result<(), DhcpError> {
        let lease = match self.lease.as_ref() {
            Some(l) => l,
            None => {
                log::error!(
                    "BUG: Got empty lease but in DhcpV4State::Rebooting, \
                     rollback to DhcpV4State::InitReboot"
                );
                self.state = DhcpV4State::InitReboot;
                return Ok(());
            }
        };
        let dhcp_msg = DhcpV4Message::new_reboot(self.xid, &self.config, lease);
        let xid = self.xid;
        let raw_socket = self.get_raw_socket_or_init().await?;

        log::debug!("Sending broadcast DHCPREQUEST to verify cached lease");

        raw_socket
            .send(&dhcp_msg.to_eth_packet_broadcast()?)
            .await?;

        log::debug!("Waiting DHCP server reply with DHCPACK or DHCPNAK");
        // Make sure we wait all reply from DHCP server instead of
        // failing on first DHCP invalid reply
        loop {
            match raw_socket.recv_dhcp_reply(xid).await {
                Ok(Some(DhcpV4Reply::Ack(l))) => {
                    log::debug!("Cached lease confirmed by DHCP server");
                    self.done(*l)?;
                    return Ok(());
                }
                Ok(Some(DhcpV4Reply::Nak)) => {
                    log::info!(
                        "Cached lease rejected by DHCP server (DHCPNAK), \
                         requesting a new lease"
                    );
                    self.lease = None;
                    self.retry_count = 0;
                    self.state = DhcpV4State::InitReboot;
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
