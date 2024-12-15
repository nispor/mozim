## RFC 8415

Clients and servers exchange DHCP messages using UDP (see [RFC768]
and BCP 145 [RFC8085]).  The client uses a link-local address or
addresses determined through other mechanisms for transmitting and
receiving DHCP messages.

`All_DHCP_Relay_Agents_and_Servers`: ff02::1:2
`All_DHCP_Servers`: ff05::1:3

Clients listen for DHCP messages on UDP port 546.  Servers and relay
agents listen for DHCP messages on UDP port 547.



                Server                          Server
            (not selected)      Client        (selected)

                  v               v               v
                  |               |               |
                  |     Begins initialization     |
                  |               |               |
     start of     | _____________/|\_____________ |
     4-message    |/ Solicit      | Solicit      \|
     exchange     |               |               |
              Determines          |          Determines
             configuration        |         configuration
                  |               |               |
                  |\              |  ____________/|
                  | \________     | /Advertise    |
                  | Advertise\    |/              |
                  |           \   |               |
                  |      Collects Advertises      |
                  |             \ |               |
                  |     Selects configuration     |
                  |               |               |
                  | _____________/|\_____________ |
                  |/ Request      |  Request     \|
                  |               |               |
                  |               |     Commits configuration
                  |               |               |
     end of       |               | _____________/|
     4-message    |               |/ Reply        |
     exchange     |               |               |
                  |    Initialization complete    |
                  |               |               |
                  .               .               .
                  .               .               .
                  |   T1 (renewal) timer expires  |
                  |               |               |
     2-message    | _____________/|\_____________ |
     exchange     |/ Renew        |  Renew       \|
                  |               |               |
                  |               | Commits extended lease(s)
                  |               |               |
                  |               | _____________/|
                  |               |/ Reply        |
                  .               .               .
                  .               .               .
                  |               |               |
                  |      Graceful shutdown        |
                  |               |               |
     2-message    | _____________/|\_____________ |
     exchange     |/ Release      |  Release     \|
                  |               |               |
                  |               |         Discards lease(s)
                  |               |               |
                  |               | _____________/|
                  |               |/ Reply        |
                  |               |               |
                  v               v               v


The IAID uniquely identifies the IA and MUST be chosen to be unique
among the IAIDs for that IA type on the client (e.g., an IA_NA with
an IAID of 0 and an IA_PD with an IAID of 0 are each considered
unique).  The IAID is chosen by the client.  For any given use of an
IA by the client, the IAID for that IA MUST be consistent across
restarts of the DHCP client.



       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |    msg-type   |               transaction-id                  |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      .                            options                            .
      .                 (variable number and length)                  .
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                  Figure 2: Client/Server Message Format


16.2.  Solicit Message

   Clients MUST discard any received Solicit messages.

   Servers MUST discard any Solicit messages that do not include a
   Client Identifier option or that do include a Server Identifier
   option.

16.3.  Advertise Message

   Clients MUST discard any received Advertise message that meets any of
   the following conditions:

   -  the message does not include a Server Identifier option (see
      Section 21.3).

   -  the message does not include a Client Identifier option (see
      Section 21.2).

   -  the contents of the Client Identifier option do not match the
      client's DUID.

   -  the "transaction-id" field value does not match the value the
      client used in its Solicit message.

   Servers and relay agents MUST discard any received Advertise
   messages.


16.4.  Request Message

   Clients MUST discard any received Request messages.

   Servers MUST discard any received Request message that meets any of
   the following conditions:

   -  the message does not include a Server Identifier option (see
      Section 21.3).

   -  the contents of the Server Identifier option do not match the
      server's DUID.

   -  the message does not include a Client Identifier option (see
      Section 21.2).


16.6.  Renew Message

   Clients MUST discard any received Renew messages.

   Servers MUST discard any received Renew message that meets any of the
   following conditions:

   -  the message does not include a Server Identifier option (see
      Section 21.3).

   -  the contents of the Server Identifier option do not match the
      server's identifier.

   -  the message does not include a Client Identifier option (see
      Section 21.2).

16.7.  Rebind Message

   Clients MUST discard any received Rebind messages.

   Servers MUST discard any received Rebind messages that do not include
   a Client Identifier option (see Section 21.2) or that do include a
   Server Identifier option (see Section 21.3).
