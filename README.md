# RIPS - Rust IP Stack

This project aims at becoming a full userspace implementation of a TCP/IP stack.

[ripstest](https://github.com/faern/ripstest) is a small crate with some usage examples.

# TODO

Current big step is to implement IPv4 fragmentation.

## Tests

Here is an (incomplete) list of tests that I want to write and make work.
Somewhat sorted in order of priority.

All of these tests are run towards the mocked Pnet implementation.
To make sure we don't lose track of reality too much also do some of the tests
on the real network.

- [x] Send Ethernet packet
- [x] Recv Ethernet packet
- [x] Do Arp lookup
- [ ] Send IPv4 packet to local network
- [ ] Send IPv4 packet to IP not on local network.
- [ ] Recv IPv4 packet
- [ ] Send IPv4 packet with fragmentation
- [ ] Send UDP packet
- [ ] Recv UDP packet
- [ ] Send/Recv ICMP ping
- [ ] Establish TCP connection
- [ ] Send IPv6 packet

## Layer 3 - Network layer

Here is a quite messy and far from complete todo list for layer 3. The stuff here is not in any priority or difficulty order.

- [x] Interface towards layer 2
  * [x] Support libpnet out of the box
  * [x] Easy to use any layer 2 implementation
  * [x] Mock layer 2 for testing
- [ ] Listening on multiple interfaces
- [ ] Assigning IPs and netmasks to interfaces
- [x] ARP table and lookup
- [ ] Message fragmentation on large packets
- [ ] Support sending these types of packets
  * [ ] IPv4
  * [ ] IPv6
  * [x] ARP
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
