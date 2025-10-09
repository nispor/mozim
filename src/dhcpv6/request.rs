// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use super::{
    msg::{DhcpV6Message, DhcpV6MessageType},
    time::gen_retransmit_time,
    DhcpV6Config, DhcpV6Lease, DhcpV6State,
};
use crate::{DhcpError, DhcpV6Client, DhcpV6Option, ErrorKind};

// RFC 8415 section 7.6 Transmission and Retransmission Parameters
const REQ_TIMEOUT: Duration = Duration::from_secs(1);
const REQ_MAX_RT: Duration = Duration::from_secs(30);
const REQ_MAX_RC: u32 = 10;

impl DhcpV6Client {
    fn gen_request_wait_time(&self) -> Option<Duration> {
        gen_retransmit_time(
            self.trans_begin_time,
            self.retransmit_count,
            self.retransmit_timeout,
            REQ_TIMEOUT,
            REQ_MAX_RT,
            REQ_MAX_RC,
            Duration::new(0, 0),
        )
    }

    pub(crate) async fn request(&mut self) -> Result<(), DhcpError> {
        if self.retransmit_count == 0 {
            self.trans_begin_time = Instant::now();
            self.regen_xid();
        }

        loop {
            self.retransmit_timeout =
                if let Some(t) = self.gen_request_wait_time() {
                    t
                } else {
                    log::info!(
                        "Exceeded maximum wait time for Request stage, \
                         rollback to Solicit stage"
                    );
                    self.clean_up();
                    return Ok(());
                };

            match tokio::time::timeout(self.retransmit_timeout, self._request())
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
                         Request, retrying",
                        self.retransmit_timeout.as_secs(),
                    );
                    self.retransmit_count += 1;
                }
            }
        }
    }

    async fn _request(&mut self) -> Result<(), DhcpError> {
        self.state = DhcpV6State::Request;
        self.lease = None;
        let xid = self.xid;
        let pending_lease = if let Some(l) = self.pending_lease.as_ref() {
            l
        } else {
            return Err(DhcpError::new(
                ErrorKind::Bug,
                format!("No pending lease for DhcpV6State::Request {self:?}"),
            ));
        };
        let dhcp_packet = new_request_msg(
            self.xid,
            &self.config,
            &self.trans_begin_time,
            pending_lease,
        );
        let udp_socket = self.get_udp_socket_or_init().await?;

        log::debug!("Sending Request");
        log::trace!("Sending Request {dhcp_packet:?}");

        // TODO(Gris Ge): OPTION_UNICAST
        //      For Request, Renew, Information-request, Release, and Decline
        //      messages, it is allowed only if the Server Unicast option is
        //      configured.
        udp_socket.send_multicast(&dhcp_packet.emit()).await?;
        log::debug!("Waiting server reply with Reply");
        // Make sure we wait all reply from DHCP server instead of
        // failing on first DHCP invalid reply
        loop {
            match udp_socket
                .recv_dhcp_lease(DhcpV6MessageType::Reply, xid)
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

fn new_request_msg(
    xid: u32,
    config: &DhcpV6Config,
    trans_begin_time: &Instant,
    lease: &DhcpV6Lease,
) -> DhcpV6Message {
    let mut ret = DhcpV6Message::new(
        DhcpV6MessageType::Request,
        xid,
        &config.duid,
        trans_begin_time,
    );
    ret.options.insert(DhcpV6Option::OptionRequestOption(
        config.request_opts.clone(),
    ));
    ret.load_lease(lease);

    ret
}
