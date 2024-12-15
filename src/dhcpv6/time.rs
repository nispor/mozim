// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use rand::Rng;

use crate::{DhcpError, ErrorKind};

// RFC 8415 section 7.6 Transmission and Retransmission Parameters
const SOL_TIMEOUT: Duration = Duration::from_secs(1);
const SOL_MAX_RT: Duration = Duration::from_secs(3600);
const REQ_TIMEOUT: Duration = Duration::from_secs(1);
const REQ_MAX_RT: Duration = Duration::from_secs(30);
const REQ_MAX_RC: u32 = 10;
const REN_TIMEOUT: Duration = Duration::from_secs(10);
const REN_MAX_RT: Duration = Duration::from_secs(600);
const REB_TIMEOUT: Duration = Duration::from_secs(10);
const REB_MAX_RT: Duration = Duration::from_secs(600);

// RFC 8415 section 15.  Reliability of Client-Initiated Message Exchanges
//  RT      Retransmission timeout
//  IRT     Initial retransmission time
//  MRC     Maximum retransmission count
//  MRT     Maximum retransmission time
//  MRD     Maximum retransmission duration
//  RAND    Randomization factor
fn gen_retransmit_time(
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
            (irt.as_millis() * rand::thread_rng().gen_range(900..1100) / 1000)
                .try_into()
                .unwrap_or(u64::MAX),
        )
    } else {
        Duration::from_millis(
            (rt.as_millis() * rand::thread_rng().gen_range(1900..2100) / 1000)
                .try_into()
                .unwrap_or(u64::MAX),
        )
    };

    if mrt != Duration::new(0, 0) && rt > mrt {
        Some(Duration::from_millis(
            (mrt.as_millis() * rand::thread_rng().gen_range(900..1100) / 1000)
                .try_into()
                .unwrap_or(u64::MAX),
        ))
    } else {
        Some(rt)
    }
}

pub(crate) fn gen_solicit_wait_time(
    trans_begin_time: Instant,
    retransmit_count: u32,
    previous_wait_time: Duration,
) -> Result<Duration, DhcpError> {
    match gen_retransmit_time(
        trans_begin_time,
        retransmit_count,
        previous_wait_time,
        SOL_TIMEOUT,
        SOL_MAX_RT,
        0,
        Duration::new(0, 0),
    ) {
        Some(rt) => Ok(rt),
        None => Err(DhcpError::new(
            ErrorKind::Timeout,
            "Timeout on waiting DHCPv6 reply on SOLICIT message".to_string(),
        )),
    }
}

pub(crate) fn gen_request_wait_time(
    trans_begin_time: Instant,
    retransmit_count: u32,
    previous_wait_time: Duration,
) -> Result<Duration, DhcpError> {
    match gen_retransmit_time(
        trans_begin_time,
        retransmit_count,
        previous_wait_time,
        REQ_TIMEOUT,
        REQ_MAX_RT,
        REQ_MAX_RC,
        Duration::new(0, 0),
    ) {
        Some(rt) => Ok(rt),
        None => Err(DhcpError::new(
            ErrorKind::Timeout,
            "Timeout on waiting DHCPv6 reply on REQUEST message".to_string(),
        )),
    }
}

pub(crate) fn gen_renew_wait_time(
    trans_begin_time: Instant,
    retransmit_count: u32,
    previous_wait_time: Duration,
    t2: Duration,
) -> Result<Duration, DhcpError> {
    match gen_retransmit_time(
        trans_begin_time,
        retransmit_count,
        previous_wait_time,
        REN_TIMEOUT,
        REN_MAX_RT,
        0,
        t2,
    ) {
        Some(rt) => Ok(rt),
        None => Err(DhcpError::new(
            ErrorKind::Timeout,
            "Timeout on waiting DHCPv6 reply on RENEW message".to_string(),
        )),
    }
}

pub(crate) fn gen_rebind_wait_time(
    trans_begin_time: Instant,
    retransmit_count: u32,
    previous_wait_time: Duration,
    valid_life: Duration,
) -> Result<Duration, DhcpError> {
    match gen_retransmit_time(
        trans_begin_time,
        retransmit_count,
        previous_wait_time,
        REB_TIMEOUT,
        REB_MAX_RT,
        0,
        valid_life,
    ) {
        Some(rt) => Ok(rt),
        None => Err(DhcpError::new(
            ErrorKind::Timeout,
            "Timeout on waiting DHCPv6 reply on REBIND message".to_string(),
        )),
    }
}
