// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use rand::Rng;

// The T1/T2 randomization is done by server side according to RFC 2131:
//      Times T1 and T2 SHOULD be chosen with some random "fuzz" around a fixed
//      value, to avoid synchronization of client reacquisition.
pub(crate) fn gen_renew_rebind_times(t1: u32, t2: u32, lease: u32) -> [u32; 4] {
    [t1, t1 + (t2 - t1) / 2, t2, t2 + (lease - t2) / 2]
}

// RFC 2131, section 4.1 "Constructing and sending DHCP messages" has
// retransmission guideline.
// It should be starting with 4 seconds and double of previous delay, up to 64
// seconds. Delay should be randomized from range -1 to 1;
pub(crate) fn gen_dhcp_request_delay(retry_count: u32) -> u32 {
    let mut base = 2u64.pow(retry_count + 2) - 1;
    if base > 62 {
        base = 62;
    }
    let ms: u64 = rand::thread_rng().gen_range(0..2000);
    (Duration::from_secs(base) + Duration::from_millis(ms))
        .as_secs()
        .try_into()
        .unwrap_or(u32::MAX)
}
