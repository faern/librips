# Rips - Rust IP Stack

[`rips`](https://github.com/faern/librips) is a TCP/IP stack implemented in Rust and backed by
[`libpnet`](https://github.com/libpnet/libpnet) for its raw ethernet access.

**WARNING**: This is not a *complete* TCP/IP stack at the moment.
It's a work in progress. Continue to read to see what works at the moment.
Feedback and ideas on the implementation and this documentation is very welcome. This is my
first TCP/IP stack implementation and I'm not extremely experienced in Rust either, so
help will probably be needed in order to make this library complete and correct.
Most of this is implemented from observations of how other stacks seem to work, I have not
studied any other implementations in detail.

Linux and OS X builds:
[![Build Status](https://api.travis-ci.org/faern/librips.svg?branch=master)](https://travis-ci.org/faern/librips)

- [rnetcat](https://github.com/faern/rnetcat) - A Netcat like program based on rips.
- [ripstest](https://github.com/faern/ripstest) - A small crate with some usage examples of
  different layers of rips.

## Examples

```rust
let stack = rips::default_stack();
```

## Features

An incomplete list of what rips supports and is missing at the moment.

- [x] Sending and receiving Ethernet frames
- [x] Arp
  - [x] Sending
  - [x] Parsing incoming responses
  - [ ] Timing out old entries in table
- [ ] IPv4
  - [x] Standard send
  - [x] Validate lengths and checksums as part of parsing incoming
  - [ ] Fragmenting outgoing packets
    - [x] Works in standard case
    - [ ] Correctly picking an identification field
  - [ ] Reassembling incoming packets
    - [x] Works in standard case
    - [ ] Timing out caches of packets that were never completed
    - [ ] Support reassemble out of order fragments?
  - [ ] Header options
  - [ ] Routing
    - [x] Works in standard case
    - [ ] Invalidate existing Tx on update
    - [ ] Metrics
  - [ ] Possible to change TTL
- [ ] IPv6
  - [ ] Path MTU discovery
- [ ] Icmp
  - [ ] Send generic Icmp packet
  - [ ] Send Echo Request
  - [ ] Receive Echo Reply
  - [ ] Provide convenient way to implement a ping alternative
- [ ] Udp
  - [x] Sending Udp packets
  - [x] Provide API similar to Rusts standard `UdpSocket`
  - [ ] Provide improved API for separated sending and receiving
  - [ ] Correctly close and clean up closed sockets
- [ ] Tcp

## Architecture and terminology

### Sending

Rips contains a number of structs with names ending in *Tx*,
eg. `EthernetTx`, `ArpTx`, `Ipv4Tx`, `UdpTx`. We call them *tx-objects*, or transmit objects.
The tx-objects are building the header for their protocols and are supposed to be as simple
as possible.
The constructors of the tx-objects take an instance of a tx-object belonging to the underlying
protocol, eg. both `ArpTx` and `Ipv4Tx` takes an `EthernetTx`,
while `UdpTx` takes an `Ipv4Tx`[1].
The constructors also take whatever values are needed to build their respective packets,
usually source and destination addresses and similar.

At the bottom of the stack there is a `Tx` instance for every interface in the stack.
View the `Tx` struct as the base tx-object.
The `Tx` holds the sending part of the `pnet` backend and a simple counter behind a `Mutex`.
Whenever anything in the stack changes, such as updates to the Arp or routing tables,
the counter inside the `Tx` is incremented automatically by the stack. The `Tx` also holds the
counter value from when it was created. When any tx-object is used to send a packet the sending
will propagate down and eventually reach the `Tx` at the bottom. There the `Mutex` is locked
and the counter from the creation of that `Tx` is compared to the counter behind the lock.
If the counters are equal the packet is transmitted on the network, otherwise a
TxError::InvalidTx is returned. The reason for this is that every tx-object should be kept
simple and not do any lookups against routing tables etc when they construct their packets.
As long as nothing changes inside the stack all transmissions can go ahead with no locking or
lookups inside their `send` methods. As soon as a change happens inside the stack all existing
tx-objects become invalid and must be recreated (which is cheap).

[1]: This will change when IPv6 is implemented so that `UdpTx` can be used on top of both.

### Receiving

Just as every protocol in the stack has a struct whose name ends in *Tx* for transmission,
it has a corresponding struct ending in *Rx* that is used for parsing incoming packets.

The rx-objects behave a little bit different on different levels of the stack. At the bottom
the listeners are fixed and given in the constructor to avoid locking at each level on every
incoming packets. Further up the stack the listeners are `HashMap`s behind `Mutex`es
that can be changed throughout the life of the stack to accomodate added and removed sockets.

Work will be done to reduce locking on the receiving end. However, optimization comes after
functionality, so that will be done later.

### tests

This crate contains both unit tests and integration tests, both placed where the Rust book
recommends them to be. The problem is that I need to do some mocking in the unit tests
to be able to swap out the real dependencies with fake ones, so I can test individual structs
without initializing too many other structs. At the moment this is solved with conditional
compilation. When the feature "unit-tests" is active dependencies will be swapped out for
mocks that exist in `rips::test`.

The bundled script `test.sh` is a tiny script that will execute both the unit tests and the
integration tests.

Ideas on how to solve this in a better way is welcome. However, the requirements are that
the solution does not bloat the production version of the code noticeably. Static dispatch
can't be changed into dynamic dispatch just to allow testing.

## Unsolved Questions

Here are a few problems that I ran into that I still did not solve. Feedback is welcome.

* If it's possible to have the same IP on multiple interfaces, which one will a
  socket bound to that local IP receive packets from?
* Should the IP layer reassemble fragmented packets that are out of order?
* Should the `FooTx` structs not contain the underlying `BarTx` and do the sending internally.
  But instead be agnostic of the underlying protocol.

