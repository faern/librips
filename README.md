# librips

`librips` is a TCP/IP stack implemented in Rust.

**WARNING**: This is not a *complete* TCP/IP stack at the moment.
It's a work in progress. Continue to read to see what works at the moment

Linux and OS X builds:
[![Build Status](https://api.travis-ci.org/faern/librips.svg?branch=master)](https://travis-ci.org/faern/librips)

- [rnetcat](https://github.com/faern/rnetcat) - A Netcat like program based on rips.
- [ripstest](https://github.com/faern/ripstest) - A small crate with some usage examples of
  different layers of rips.

## Features

An incomplete list of what is rips supports and is missing at the moment.

- [x] Sending and receiving Ethernet frames
- [x] Arp
  - [x] Sending
  - [x] Parsing incoming responses
- [ ] IPv6
- [ ] TCP

## Unsolved Questions

Here are a few problems that I ran into that I still did not solve. Input welcome.

* If it's possible to have the same IP on multiple interfaces, which one will a
  socket bound to that local IP receive packets from?
* Should the IP layer reassemble fragmented packets that are out of order?
