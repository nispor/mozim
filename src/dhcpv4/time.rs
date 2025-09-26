// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use crate::{DhcpError, DhcpTimer, DhcpV4Client, DhcpV4Lease};

pub(crate) const MIN_REBIND_RENEW_WAIT_TIME: Duration = Duration::from_secs(60);

impl DhcpV4Client {
    // TODO(Gris Ge): validate T1 T2 and lease according to RFC 2131 mandates.
    pub(crate) fn set_lease_timer(
        &mut self,
        lease: &DhcpV4Lease,
    ) -> Result<(), DhcpError> {
        self.t1_timer =
            Some(DhcpTimer::new(Duration::from_secs(lease.t1_sec.into()))?);
        self.t2_timer =
            Some(DhcpTimer::new(Duration::from_secs(lease.t2_sec.into()))?);
        self.lease_timer = Some(DhcpTimer::new(Duration::from_secs(
            lease.lease_time_sec.into(),
        ))?);
        Ok(())
    }
}
