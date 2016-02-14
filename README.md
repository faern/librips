# RIPS - Rust IP Stack

This project aims at becoming a full userspace implementation of a TCP/IP stack.

# TODO

## Layer 3 - Network layer

Here is a quite messy and far from complete todo list for layer 3. The stuff here is not in any priority or difficulty order.

- [ ] Interface towards layer 2
  * [ ] Support libpnet out of the box
  * [ ] Easy to use any layer 2 implementation
  * [ ] Mock layer 2 for testing
- [ ] Listening on multiple interfaces
- [ ] Assigning IPs and netmasks to interfaces
- [ ] ARP table and lookup
- [ ] Message fragmentation on large packets
- [ ] Support sending these types of packets
  * [ ] IPv4
  * [ ] IPv6
  * [ ] ARP
  * [ ] RARP
  * [ ] Wake on Lan
- [ ] Routing table struct and impl
  * [ ] IPv4
  * [ ] IPv6
- [ ] Checksumming - Do in separate crate
- [ ] API to user
  * [ ] Sending
  * [ ] Receiving

## Layer 4 - Transport layer

- [ ] Research and plan what is needed for layer 4
