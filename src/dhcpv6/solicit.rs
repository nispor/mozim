// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use super::{
    msg::{DhcpV6Message, DhcpV6MessageType},
    time::gen_retransmit_time,
    DhcpV6Config, DhcpV6State,
};
use crate::{
    DhcpError, DhcpV6Client, DhcpV6Mode, DhcpV6Option, DhcpV6OptionIaPd,
    ErrorKind,
};

// RFC 8415 section 7.6 Transmission and Retransmission Parameters
const SOL_MAX_DELAY_MS: u64 = 1000; // SOL_MAX_DELAY in milliseconds
const SOL_TIMEOUT: Duration = Duration::from_secs(1);
const SOL_MAX_RT: Duration = Duration::from_secs(3600);

impl DhcpV6Client {
    fn gen_solicit_wait_time(&self) -> Option<Duration> {
        gen_retransmit_time(
            self.trans_begin_time,
            self.retransmit_count,
            self.retransmit_timeout,
            SOL_TIMEOUT,
            SOL_MAX_RT,
            0,
            Duration::new(0, 0),
        )
    }

    pub(crate) async fn solicit(&mut self) -> Result<(), DhcpError> {
        // RFC 8415, 18.2.1. Creation and Transmission of Solicit Messages
        //    The first Solicit message from the client on the interface SHOULD
        //    be delayed by a random amount of time between 0 and
        //    SOL_MAX_DELAY.
        if self.retransmit_count == 0 {
            self.trans_begin_time = Instant::now();
            let wait_time_ms: u64 = rand::random_range(0..SOL_MAX_DELAY_MS);
            log::info!(
                "Waiting {wait_time_ms} miliseconds before start initial \
                 Solicit",
            );

            tokio::time::sleep(std::time::Duration::from_millis(wait_time_ms))
                .await;
        }
        // TODO(Gris Ge): Once received the same SOL_MAX_DELAY from all
        // DHCP servers before timeout, we should store it instead of using
        // default value for next retransmission timeout generation.
        loop {
            self.retransmit_timeout =
                if let Some(t) = self.gen_solicit_wait_time() {
                    t
                } else {
                    return Err(DhcpError::new(
                        ErrorKind::Bug,
                        "gen_solicit_wait_time() is expected to no max timeout"
                            .to_string(),
                    ));
                };

            match tokio::time::timeout(self.retransmit_timeout, self._solicit())
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
                        "Timeout({}s) on waiting DHCP server Advertise reply \
                         for Solicit, retrying",
                        self.retransmit_timeout.as_secs(),
                    );
                    self.retransmit_count += 1;
                }
            }
        }
    }

    async fn _solicit(&mut self) -> Result<(), DhcpError> {
        self.state = DhcpV6State::Solicit;
        self.lease = None;
        let dhcp_packet =
            new_solicit_msg(self.xid, &self.config, &self.trans_begin_time);
        let xid = self.xid;
        let udp_socket = self.get_udp_socket_or_init().await?;

        log::debug!("Sending Solicit");
        log::trace!("Sending Solicit {dhcp_packet:?}");

        udp_socket.send_multicast(&dhcp_packet.emit()).await?;
        log::debug!("Waiting server reply with Advertise");
        // Make sure we wait all reply from DHCP server instead of
        // failing on first DHCP invalid reply
        loop {
            // TODO(Gris Ge): Server might reply with `Reply` for
            // `OPTION_RAPID_COMMIT`. Since we never set so, it is OK to assume
            // server only reply with Advertise.
            match udp_socket
                .recv_dhcp_lease(DhcpV6MessageType::Advertise, xid)
                .await
            {
                Ok(Some(l)) => {
                    // TODO(Gris Ge): It is possible for malicious DHCP server
                    // send out Advertise and do not ack on follow up
                    // Request. With current code, user will never get a
                    // valid DHCP lease. Even it might be user's fault on
                    // malicious environment, but we should provide a
                    // way to handle this in the future.
                    self.pending_lease = Some(l);
                    self.reset_retransmit_counters();
                    self.state = DhcpV6State::Request;
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

fn new_solicit_msg(
    xid: u32,
    config: &DhcpV6Config,
    trans_begin_time: &Instant,
) -> DhcpV6Message {
    let mut ret = DhcpV6Message::new(
        DhcpV6MessageType::Solicit,
        xid,
        &config.duid,
        trans_begin_time,
    );
    ret.options.insert(DhcpV6Option::OptionRequestOption(
        config.request_opts.clone(),
    ));
    match config.mode {
        DhcpV6Mode::NonTemporaryAddresses => {
            ret.options.insert(DhcpV6Option::IANA(Default::default()))
        }
        DhcpV6Mode::TemporaryAddresses => {
            ret.options.insert(DhcpV6Option::IATA(Default::default()));
        }
        DhcpV6Mode::PrefixDelegation(prefix_len_hint) => {
            ret.options.insert(DhcpV6Option::IAPD(
                DhcpV6OptionIaPd::new_with_hint(prefix_len_hint),
            ));
        }
    }

    ret
}
