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
