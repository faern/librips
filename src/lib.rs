// Copyright (c) 2016 Linus Färnstrand <faern@faern.net>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # Rips - Rust IP Stack
//!
//! [`rips`](https://github.com/faern/librips) is a TCP/IP stack implemented in
//! Rust and backed by [`libpnet`](https://github.com/libpnet/libpnet) for its
//! raw ethernet access.
//!
//! **WARNING**: This is not a *complete* TCP/IP stack at the moment.
//! It's a work in progress. Continue to read to see what works at the moment.
//! Feedback and ideas on the implementation and this documentation is very
//! welcome. This is my first TCP/IP stack implementation so help will probably
//! be needed in order to make this library complete and correct.
//! Most of this is implemented from observations of how other stacks seem to
//! work, I have not studied any other implementations in detail.
//!
//! Linux and OS X builds:
//! [![Build Status](https://api.travis-ci.org/faern/librips.
//! svg?branch=master)](https://travis-ci.org/faern/librips)
//!
//! - [rnetcat](https://github.com/faern/rnetcat) - A Netcat like program based
//! on rips.
//! - [ripstest](https://github.com/faern/ripstest) - A small crate with some
//! usage examples of different layers of rips.
//!
//! ## Usage
//!
//! ```rust,ignore
//! extern crate rips;
//!
//! let stack = rips::default_stack();
//! ...
//! ```
//!
//! ## Features
//!
//! An incomplete list of what rips supports and is missing at the moment.
//!
//! - [x] Sending and receiving Ethernet frames
//! - [x] Arp
//!   - [x] Sending
//!   - [x] Parsing incoming responses
//!   - [ ] Timing out old entries in table
//! - [ ] IPv4
//!   - [x] Standard send
//!   - [x] Validate lengths and checksums as part of parsing incoming
//!   - [ ] Fragmenting outgoing packets
//!     - [x] Works in standard case
//!     - [ ] Correctly picking an identification field
//!   - [ ] Reassembling incoming packets
//!     - [x] Works in standard case
//!     - [ ] Timing out caches of packets that were never completed
//!     - [ ] Support reassemble out of order fragments?
//!   - [ ] Header options
//!   - [ ] Routing
//!     - [x] Works in standard case
//!     - [ ] Invalidate existing Tx on update
//!     - [ ] Metrics
//!   - [ ] Possible to change TTL
//! - [ ] IPv6
//!   - [ ] Path MTU discovery
//! - [ ] Icmp
//!   - [ ] Send generic Icmp packet
//!   - [ ] Send Echo Request
//!   - [ ] Receive Echo Reply
//!   - [ ] Provide convenient way to implement a ping alternative
//! - [ ] Udp
//!   - [x] Sending Udp packets
//!   - [x] Provide API similar to Rusts standard `UdpSocket`
//!   - [ ] Provide improved API for separated sending and receiving
//!   - [ ] Correctly close and clean up closed sockets
//! - [ ] Tcp
//!
//! ## Architecture and terminology
//!
//! ### Sending
//!
//! Rips contains a number of structs with names ending in *Tx*,
//! eg. `EthernetTx`, `ArpTx`, `Ipv4Tx`, `UdpTx`. We call them *tx-objects*, or
//! transmit objects. The tx-objects are building the header for their protocols
//! and are supposed to be as simple as possible.
//! The constructors of the tx-objects take an instance of a tx-object
//! belonging to the underlying protocol, eg. both `ArpTx` and `Ipv4Tx`
//! takes an `EthernetTx`, while `UdpTx` takes an `Ipv4Tx`[1].
//! The constructors also take whatever values are needed to build their
//! respective packets, usually source and destination addresses and similar.
//!
//! At the bottom of the stack there is a `Tx` instance for every interface in
//! the stack. View the `Tx` struct as the base tx-object.
//! The `Tx` holds the sending part of the `pnet` backend and a simple counter
//! behind a `Mutex`. Whenever anything in the stack changes, such as updates
//! to the Arp or routing tables, the counter inside the `Tx` is incremented
//! automatically by the stack. The `Tx` also holds the counter value from when
//! it was created. When any tx-object is used to send a packet the sending
//! will propagate down and eventually reach the `Tx` at the bottom. There the
//! `Mutex` is locked and the counter from the creation of that `Tx` is
//! compared to the counter behind the lock.
//! If the counters are equal the packet is transmitted on the network,
//! otherwise a `TxError::InvalidTx` is returned. The reason for this is that
//! every tx-object should be kept simple and not do any lookups against routing
//! tables etc when they construct their packets.
//! As long as nothing changes inside the stack all transmissions can go ahead
//! with no locking or lookups inside their `send` methods. As soon as a change
//! happens inside the stack all existing tx-objects become invalid and must be
//! recreated (which is cheap).
//!
//! [1]: This will change when IPv6 is implemented so that `UdpTx` can be used
//! on top of both.
//!
//! ### Receiving
//!
//! Just as every protocol in the stack has a struct whose name ends in *Tx*
//! for transmission, it has a corresponding struct ending in *Rx* that is
//! used for parsing incoming packets.
//!
//! The rx-objects behave a little bit different on different levels of the
//! stack. At the bottom the listeners are fixed and given in the constructor
//! to avoid locking at each level on every incoming packets. Further up the
//! stack the listeners are `HashMap`s behind `Mutex`es that can be changed
//! throughout the life of the stack to accomodate added and removed sockets.
//!
//! Work will be done to reduce locking on the receiving end. However,
//! optimization comes after functionality, so that will be done later.
//!
//! ### tests
//!
//! This crate contains both unit tests and integration tests, both placed
//! where the Rust book recommends them to be. The problem is that I need
//! to do some mocking in the unit tests to be able to swap out the real
//! dependencies with fake ones, so I can test individual structs without
//! initializing too many other structs. At the moment this is solved
//! with conditional compilation. When the feature "unit-tests" is active
//! dependencies will be swapped out for mocks that exist in `rips::test`.
//!
//! The bundled script `test.sh` is a tiny script that will execute both the
//! unit tests and the integration tests.
//!
//! Ideas on how to solve this in a better way is welcome. However, the
//! requirements are that the solution does not bloat the production version
//! of the code noticeably. Static dispatch can't be changed into dynamic
//! dispatch just to allow testing.
//!
//! ## Unsolved Questions
//!
//! Here are a few problems that I ran into that I still did not solve.
//! Feedback is welcome.
//!
//! * If it's possible to have the same IP on multiple interfaces, which one
//!   will a socket bound to that local IP receive packets from? Both?
//! * Should the IP layer reassemble fragmented packets that are out of order?
//! * Should the `FooTx` structs not contain the underlying `BarTx` and do the
//!   sending internally. But instead be agnostic of the underlying protocol.
//!

// #![deny(missing_docs)]

extern crate rand;
extern crate pnet;
extern crate ipnetwork;

use std::io;
use std::sync::{Arc, Mutex};

#[macro_use]
extern crate log;

use pnet::datalink::{self, EthernetDataLinkSender, NetworkInterface};
use pnet::util::MacAddr;
use pnet::packet::ethernet::MutableEthernetPacket;

#[macro_use]
mod macros;

pub mod ethernet;

/// Module containing everything related to the address resolution protocol
/// (Arp)
pub mod arp;

/// Module containing IPv4 functionality
pub mod ipv4;

/// Module containing internet control message procotol (icmp) functionality
pub mod icmp;

/// Module containing Udp functionality.
pub mod udp;

mod routing;
pub use routing::RoutingTable;

mod util;

#[cfg(any(test, feature = "unit-tests", feature = "integration-tests", feature = "benchmarks"))]
pub mod testing;

#[cfg(not(feature = "unit-tests"))]
mod stack;

#[cfg(not(feature = "unit-tests"))]
pub use stack::{NetworkStack, StackError, StackResult};

pub static DEFAULT_BUFFER_SIZE: usize = 1024 * 128;

/// Representation for one network interface. More or less a subset of
/// `pnet::util::NetworkInterface`, but with guaranteed MAC address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Interface {
    /// The name of this interface. Used only for providing something readable
    /// to the user
    pub name: String,

    /// The MAC address of this interface
    pub mac: MacAddr,
}

impl Interface {
    /// Creates a new `Interface` with the given properties
    pub fn new(name: String, mac: MacAddr) -> Interface {
        Interface {
            name: name,
            mac: mac,
        }
    }
}

/// Super trait to any protocol
pub trait Protocol {
    /// Returns how many bytes this packet will occupy
    fn len(&self) -> usize;

    /// Construct this packet into the given `buffer`
    fn build(&mut self, buffer: &mut [u8]);
}

/// Represents the channel used for sending to and reading from one network
/// interface.
/// Basically a simplification of `pnet::datalink::Channel` but guaranteed to
/// be be ethernet.
pub struct EthernetChannel(pub Box<datalink::EthernetDataLinkSender>,
                           pub Box<datalink::EthernetDataLinkReceiver>);

/// Enum representing errors happening while trying to send packets to the
/// network
#[derive(Debug)]
pub enum TxError {
    /// Returned by `Tx` when trying to use an outdated `*Tx` instance. Please
    /// construct a new one
    InvalidTx,

    /// Returned when the payload does not fit in the given protocol. For
    /// example sending a
    /// packet with more than 2^16 bytes in a protocol with a 16 bit length
    /// field
    TooLargePayload,

    /// Returned when the stack was not able to lock an internal lock. Should
    /// not happen,
    /// indicates an internal error or an invalid usage of this library.
    PoisonedLock,

    /// Returned when there was an `IoError` during transmission
    IoError(io::Error),

    /// Any other error not covered by the more specific enum variants
    Other(String),
}

impl From<io::Error> for TxError {
    fn from(e: io::Error) -> Self {
        TxError::IoError(e)
    }
}

impl From<TxError> for io::Error {
    fn from(e: TxError) -> Self {
        let other = |msg| io::Error::new(io::ErrorKind::Other, msg);
        match e {
            TxError::InvalidTx => other("Outdated constructor".to_owned()),
            TxError::TooLargePayload => other("Too large payload".to_owned()),
            TxError::PoisonedLock => other("Poisoned lock".to_owned()),
            TxError::IoError(e2) => e2,
            TxError::Other(msg) => other(format!("Other: {}", msg)),
        }
    }
}

/// Type binding for the type of `Result` that a send method returns.
pub type TxResult = Result<(), TxError>;

fn io_result_to_tx_result(r: Option<io::Result<()>>) -> TxResult {
    match r {
        None => Err(TxError::Other("Insufficient buffer space".to_owned())),
        Some(ior) => {
            match ior {
                Err(e) => Err(TxError::from(e)),
                Ok(()) => Ok(()),
            }
        }
    }
}

/// Error returned by the `recv` method of `*Rx` objects when there is
/// something wrong with the
/// incoming packet.
#[derive(Debug, Eq, PartialEq)]
pub enum RxError {
    /// When nothing is listening for this packet, so it becomes silently
    /// discarded.
    NoListener(String),

    /// When a packet contains an invalid checksum.
    InvalidChecksum,

    /// When the length of the packet does not match the
    /// requirements or header content of a protocol
    InvalidLength,

    /// When other packet content is invalid.
    InvalidContent,

    /// When a lock inside the stack is poisoned so locking can't be performed.
    /// Should not happen.
    PoisonedLock,

    /// Some error that was not covered by the more specific errors in this
    /// enum.
    Other(String),
}

/// Simple type definition for return type of `recv` on `*Rx` objects.
pub type RxResult = Result<(), RxError>;

/// Internal representation of of a sending channel used for synchronization.
/// Public only because it's part of the interface of other public structs.
pub struct VersionedTx {
    sender: Box<EthernetDataLinkSender>,
    current_rev: u64,
}

impl VersionedTx {
    /// Creates a new `VersionedTx` based on the given `EthernetDataLinkSender`.
    pub fn new(sender: Box<EthernetDataLinkSender>) -> VersionedTx {
        VersionedTx {
            sender: sender,
            current_rev: 0,
        }
    }

    /// Increments the internal counter by one. Used to invalidate all `Tx`
    /// instances created
    /// towards this `VersionedTx`
    pub fn inc(&mut self) {
        self.current_rev = self.current_rev.wrapping_add(1);
        debug!("VersionedTx ticked to {}", self.current_rev);
    }
}

enum TxSender {
    Versioned(Arc<Mutex<VersionedTx>>),
    Direct(Box<EthernetDataLinkSender>),
}

/// Base representation of a the sending part of an interface. This is what an
/// `EthernetTx` send
/// to.
pub struct Tx {
    sender: TxSender,
    rev: u64,
}

impl Tx {
    /// Creates a new `Tx` based on the given `VersionedTx`. Will lock `vtx`
    /// and copy the current
    /// revision from it. This `Tx` will work for as long as the revision in
    /// `vtx` does not change.
    pub fn versioned(vtx: Arc<Mutex<VersionedTx>>) -> Tx {
        let rev = vtx.lock().expect("Unable to lock vtx").current_rev;
        Tx {
            sender: TxSender::Versioned(vtx),
            rev: rev,
        }
    }

    /// Creates a new `Tx` based directly on the given
    /// `EthernetDataLinkSender`. Does not do
    /// versioning and should only be used for tests and other special cases.
    pub fn direct(sender: Box<EthernetDataLinkSender>) -> Tx {
        Tx {
            sender: TxSender::Direct(sender),
            rev: 0,
        }
    }

    /// Sends packets to the backing `EthernetDataLinkSender`. If this `Tx` is
    /// versioned the
    /// `VersionedTx` will first be locked and the revision compared. If the
    /// revision changed
    /// this method will return `TxError::InvalidTx` instead of sending
    /// anything.
    pub fn send<T>(&mut self, num_packets: usize, size: usize, builder: T) -> TxResult
        where T: FnMut(MutableEthernetPacket)
    {
        match self.sender {
            TxSender::Versioned(ref vtx) => {
                match vtx.lock() {
                    Ok(mut sender) => {
                        if self.rev != sender.current_rev {
                            Err(TxError::InvalidTx)
                        } else {
                            Self::internal_send(&mut sender.sender, num_packets, size, builder)
                        }
                    }
                    Err(_) => Err(TxError::PoisonedLock),
                }
            }
            TxSender::Direct(ref mut s) => Self::internal_send(s, num_packets, size, builder),
        }
    }

    fn internal_send<T>(sender: &mut Box<EthernetDataLinkSender>,
                        num_packets: usize,
                        size: usize,
                        mut builder: T)
                        -> TxResult
        where T: FnMut(MutableEthernetPacket)
    {
        let result = sender.build_and_send(num_packets, size, &mut builder);
        io_result_to_tx_result(result)
    }
}

/// Create a default stack managing all interfaces given by
/// `pnet::datalink::interfaces()`.
#[cfg(not(feature = "unit-tests"))]
pub fn default_stack() -> StackResult<NetworkStack> {
    let mut stack = NetworkStack::new();
    for interface in datalink::interfaces() {
        if let Ok(rips_interface) = convert_interface(&interface) {
            let mut config = datalink::Config::default();
            config.write_buffer_size = DEFAULT_BUFFER_SIZE;
            config.read_buffer_size = DEFAULT_BUFFER_SIZE;
            let channel = match try!(datalink::channel(&interface, config)
                .map_err(StackError::from)) {
                datalink::Channel::Ethernet(tx, rx) => EthernetChannel(tx, rx),
                _ => unreachable!(),
            };
            try!(stack.add_interface(rips_interface, channel));
        }
    }
    Ok(stack)
}

// #[cfg(not(feature = "unit-tests"))]
// pub fn stack<Datalink>(_datalink_provider: Datalink) ->
// StackResult<NetworkStack>
//     where Datalink: datalink::Datalink
// {
//     let mut stack = NetworkStack::new();
//     for interface in Datalink::interfaces() {
//         if let Ok(rips_interface) = convert_interface(&interface) {
//             let config = Datalink::default_config();
// let channel = match try!(Datalink::channel(&interface,
// config).map_err(|e| StackError::from(e))) {
// datalink::Channel::Ethernet(tx, rx) => EthernetChannel(tx,
// rx),
//                 _ => unreachable!(),
//             };
//             try!(stack.add_interface(rips_interface, channel));
//         }
//     }
//     Ok(stack)
// }
//
// #[cfg(not(feature = "unit-tests"))]
// pub fn default_stack() -> StackResult<NetworkStack> {
//     stack(datalink::DefaultDatalink)
// }

/// Converts a pnet `NetworkInterface` into a rips `Interface`.
/// Will fail if the given `NetworkInterface` does not have an associated MAC
/// address.
/// Can be changed into a `TryFrom` impl when that trait is stabilized
pub fn convert_interface(interface: &NetworkInterface) -> Result<Interface, ()> {
    if let Some(mac) = interface.mac {
        Ok(Interface {
            name: interface.name.clone(),
            mac: mac,
        })
    } else {
        Err(())
    }
}
