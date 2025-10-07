// SPDX-License-Identifier: Apache-2.0

mod client;
mod config;
mod duid;
mod lease;
mod msg;
mod option;
mod option_ia;
mod option_status;
mod rebind;
mod renew;
mod request;
mod socket;
mod solicit;
mod state;
mod time;

pub use self::{
    client::DhcpV6Client,
    config::{DhcpV6Config, DhcpV6IaType, DhcpV6Mode},
    duid::{
        DhcpV6Duid, DhcpV6DuidEnterpriseNumber, DhcpV6DuidLinkLayerAddr,
        DhcpV6DuidLinkLayerAddrPlusTime, DhcpV6DuidUuid,
    },
    lease::DhcpV6Lease,
    option::{
        DhcpV6Option, DhcpV6OptionCode, DhcpV6OptionNtpServer,
        DhcpV6OptionUnknown,
    },
    option_ia::{
        DhcpV6OptionIaAddr, DhcpV6OptionIaNa, DhcpV6OptionIaPd,
        DhcpV6OptionIaPrefix, DhcpV6OptionIaTa,
    },
    option_status::{DhcpV6OptionStatus, DhcpV6OptionStatusCode},
    state::DhcpV6State,
};
