// Copyright (c) 2016 Linus Färnstrand <faern@faern.net>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # librips
//!
//! `librips` is a TCP/IP stack implemented in Rust.
//!
//! **WARNING**: This is not a *complete* TCP/IP stack at the moment.
//! It's a work in progress. Continue to read to see what works at the moment
//!
//! Linux and OS X builds:
//! [![Build Status](https://api.travis-ci.org/faern/librips.svg?branch=master)](https://travis-ci.org/faern/librips)
//!
//! - [rnetcat](https://github.com/faern/rnetcat) - A Netcat like program based on rips.
//! - [ripstest](https://github.com/faern/ripstest) - A small crate with some usage examples of
//!   different layers of rips.
//!
//! ## Features
//!
//! An incomplete list of what is rips supports and is missing at the moment.
//!
//! - [x] Sending and receiving Ethernet frames
//! - [x] Arp
//!   - [x] Sending
//!   - [x] Parsing incoming responses
//! - [ ] IPv6
//! - [ ] TCP
//!
//! ## Unsolved Questions
//!
//! Here are a few problems that I ran into that I still did not solve. Input welcome.
//!
//! * If it's possible to have the same IP on multiple interfaces, which one will a
//!   socket bound to that local IP receive packets from?
//! * Should the IP layer reassemble fragmented packets that are out of order?
//!

// #![deny(missing_docs)]
#[allow(unused_imports)]

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

pub mod arp;

pub mod ipv4;

pub mod icmp;

pub mod udp;

mod routing;
pub use routing::RoutingTable;

mod util;

#[cfg(any(test, feature = "integration-tests"))]
pub mod test;

#[cfg(not(feature = "unit-tests"))]
mod stack;

#[cfg(not(feature = "unit-tests"))]
pub use stack::{NetworkStack, StackError, StackResult};


#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Interface {
    pub name: String,
    pub mac: MacAddr,
}

impl Interface {
    pub fn new(name: String, mac: MacAddr) -> Interface {
        Interface {
            name: name,
            mac: mac,
        }
    }
}

pub struct EthernetChannel(pub Box<datalink::EthernetDataLinkSender>,
                           pub Box<datalink::EthernetDataLinkReceiver>);

#[derive(Debug)]
pub enum TxError {
    InvalidTx,
    TooLargePayload,
    PoisonedLock,
    IoError(io::Error),
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
            TxError::InvalidTx => other(format!("Outdated constructor")),
            TxError::TooLargePayload => other(format!("Too large payload")),
            TxError::PoisonedLock => other(format!("Poisoned lock")),
            TxError::IoError(e2) => e2,
            TxError::Other(msg) => other(format!("Other: {}", msg)),
        }
    }
}

pub type TxResult = Result<(), TxError>;

fn io_result_to_tx_result(r: Option<io::Result<()>>) -> TxResult {
    match r {
        None => Err(TxError::Other(format!("Insufficient buffer space"))),
        Some(ior) => {
            match ior {
                Err(e) => Err(TxError::from(e)),
                Ok(()) => Ok(()),
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum RxError {
    NoListener(String),

    /// When a packet contains an invalid checksum
    InvalidChecksum,

    /// When the length of the packet does not match the
    /// requirements or header content of a protocol
    InvalidLength,

    /// When other packet content is invalid
    InvalidContent,

    /// When a lock inside the stack is poisoned so locking can't be performed. Should not happen.
    PoisonedLock,
    Other(String),
}

pub type RxResult = Result<(), RxError>;

pub struct VersionedTx {
    sender: Box<EthernetDataLinkSender>,
    current_rev: u64,
}

impl VersionedTx {
    pub fn new(sender: Box<EthernetDataLinkSender>) -> VersionedTx {
        VersionedTx {
            sender: sender,
            current_rev: 0,
        }
    }

    pub fn inc(&mut self) {
        self.current_rev = self.current_rev.wrapping_add(1);
        debug!("VersionedTx ticked to {}", self.current_rev);
    }
}

enum TxSender {
    Versioned(Arc<Mutex<VersionedTx>>),
    Direct(Box<EthernetDataLinkSender>),
}

pub struct Tx {
    sender: TxSender,
    rev: u64,
}

impl Tx {
    pub fn versioned(vtx: Arc<Mutex<VersionedTx>>) -> Tx {
        let rev = vtx.lock().expect("Unable to lock StackInterface::tx").current_rev;
        Tx {
            sender: TxSender::Versioned(vtx),
            rev: rev,
        }
    }

    pub fn direct(sender: Box<EthernetDataLinkSender>) -> Tx {
        Tx {
            sender: TxSender::Direct(sender),
            rev: 0,
        }
    }

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

// #[cfg(not(feature = "unit-tests"))]
// pub fn stack<Datalink>(_datalink_provider: Datalink) -> StackResult<NetworkStack>
//     where Datalink: datalink::Datalink
// {
//     let mut stack = NetworkStack::new();
//     for interface in Datalink::interfaces() {
//         if let Ok(rips_interface) = convert_interface(&interface) {
//             let config = Datalink::default_config();
//             let channel = match try!(Datalink::channel(&interface, config).map_err(|e| StackError::from(e))) {
//                 datalink::Channel::Ethernet(tx, rx) => EthernetChannel(tx, rx),
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
/// Will fail if the given NetworkInterface does not have an associated MAC address.
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
