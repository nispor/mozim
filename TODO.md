- DHCPv6 client accepts Advertise/Reply without checking a Server
  Identifier is present or that Client Identifier matches the
  client's own DUID (RFC 8415 section 16.3, 16.10).
  `recv_dhcp_lease()` (`src/dhcpv6/socket.rs`) only checks xid and
  message type; `DhcpV6Lease::new_from_msg()`
  (`src/dhcpv6/lease.rs`) copies whatever `ClientId`/`ServerId`
  option is present without comparing it to `self.config.duid`.
  A host that observes the multicast Solicit/Request (or guesses
  the 24-bit xid) can inject a forged reply.
- DHCPv6 IA_PD delegated prefix length is never validated.
  `DhcpV6OptionIaPrefix::parse()` (`src/dhcpv6/option_ia.rs`)
  reads `prefix_len` as a raw wire `u8` (0-255) and
  `DhcpV6Lease::sanitize_lease()` (`src/dhcpv6/lease.rs`) checks
  T1/T2/lifetimes/address/srv_duid but never rejects
  `prefix_len > 128`, an impossible IPv6 prefix.
- DHCPv4 client never recognizes DHCPNAK. `recv_dhcp_lease()`
  (`src/dhcpv4/socket.rs`) only compares the reply against one
  `expected` message type, so a NACK during Request/Renew/Rebind
  is dropped like any other mismatched packet instead of
  restarting configuration immediately, as RFC 2131 section 4.4.5
  requires.
- DHCPv6 retransmission backoff collapses due to integer
  truncation. `gen_retransmit_time()` (`src/dhcpv6/time.rs`)
  computes `duration.as_millis() / 1000` before multiplying by
  the jitter factor; whenever the running timeout is under
  1000ms (common for Solicit/Request, whose base is 1s +/-10%),
  the result truncates to exactly 0 and the backoff resets to the
  baseline instead of doubling (RFC 8415 section 15). Simulating
  the exact algorithm: 200/200 runs hit a zero-collapse, and only
  ~49% of Solicit runs and ~66% of Request runs approached their
  max backoff (3600s/30s) within their retry budget. Renew/Rebind
  (10s base) are unaffected.
- DHCPv4 client does not support Option Overload (option 52).
  `DhcpV4Message::parse()` (`src/dhcpv4/msg.rs`) only parses the
  fixed options area; options a server places in `sname`/`file`
  per RFC 2131 section 3 / RFC 2132 section 9.3 are invisible to
  the parser.
- DHCPv4 repeated options overwrite instead of concatenating.
  `DhcpV4Options::insert()` (`src/dhcpv4/option.rs`) stores one
  value per code in a `HashMap`, so a second TLV instance with
  the same code replaces the first instead of being concatenated
  per RFC 3396. Affects any option value long enough to need
  splitting across multiple 255-byte options (e.g. many
  classless routes).
