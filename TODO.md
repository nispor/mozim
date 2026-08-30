- Lacking integration test without `netlink` feature. The
  4 netns integ tests create clients by interface name only and
  `unwrap()` on `init()`, which needs `resolve()`; built with
  `--no-default-features` they all fail. CI only runs
  `cargo build --no-default-features` (never tests), so the gap is
  invisible. Options: gate those tests on `feature = "netlink"`,
  or add an integ test using manual `set_iface_index()` +
  `set_iface_mac_raw()` to cover the no-netlink path.
- DHCPv6 domain names reject RFC 1035 compressed/pointer-style
  labels (RFC 1035 section 4.1.4); parsing returns
  `InvalidDhcpMessage` when the high two bits of a label length
  are set.
