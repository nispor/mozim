// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use crate::{DhcpError, DhcpTimer, DhcpV6Client, DhcpV6Lease};

// RFC 8415 section 15.  Reliability of Client-Initiated Message Exchanges
//  RT      Retransmission timeout
//  IRT     Initial retransmission time
//  MRC     Maximum retransmission count
//  MRT     Maximum retransmission time
//  MRD     Maximum retransmission duration
//  RAND    Randomization factor
pub(crate) fn gen_retransmit_time(
    trans_begin_time: Instant,
    retransmit_count: u32,
    rt: Duration,
    irt: Duration,
    mrt: Duration,
    mrc: u32,
    mrd: Duration,
) -> Option<Duration> {
    if mrc != 0 && mrc < retransmit_count {
        return None;
    }
    if mrd != Duration::new(0, 0) && mrd < trans_begin_time.elapsed() {
        return None;
    }

    let rt = if rt == Duration::new(0, 0) {
        Duration::from_millis(
            (irt.as_millis() * rand::random_range(900..1100) / 1000)
                .try_into()
                .unwrap_or(u64::MAX),
        )
    } else {
        Duration::from_millis(
            (rt.as_millis() * rand::random_range(1900..2100) / 1000)
                .try_into()
                .unwrap_or(u64::MAX),
        )
    };

    if mrt != Duration::new(0, 0) && rt > mrt {
        Some(Duration::from_millis(
            (mrt.as_millis() * rand::random_range(900..1100) / 1000)
                .try_into()
                .unwrap_or(u64::MAX),
        ))
    } else {
        Some(rt)
    }
}

impl DhcpV6Client {
    pub(crate) fn set_lease_timer(
        &mut self,
        lease: &DhcpV6Lease,
    ) -> Result<(), DhcpError> {
        if !self.config.mode.is_temp_addr() {
            log::info!("Setting timer for T1: {} seconds", lease.t1_sec);
            log::info!("Setting timer for T2: {} seconds", lease.t2_sec);
            self.t1_timer =
                Some(DhcpTimer::new(Duration::from_secs(lease.t1_sec.into()))?);
            self.t2_timer =
                Some(DhcpTimer::new(Duration::from_secs(lease.t2_sec.into()))?);
        }
        log::info!(
            "Setting timer for lease valid: {} seconds",
            lease.valid_time_sec
        );
        self.valid_timer = Some(DhcpTimer::new(Duration::from_secs(
            lease.valid_time_sec.into(),
        ))?);
        Ok(())
    }
}
