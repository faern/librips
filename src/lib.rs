//! # librips
//!
//! `librips` is a TCP/IP stack implemented in Rust.

// #![deny(missing_docs)]
#[allow(unused_imports)]

extern crate pnet;
extern crate ipnetwork;

use std::io;
use std::sync::{Arc, Mutex};

use pnet::datalink;
use pnet::util::MacAddr;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::datalink::EthernetDataLinkSender;

pub mod ethernet;

pub mod arp;

pub mod ipv4;

// pub mod icmp;

pub mod udp;

mod routing;
pub use routing::RoutingTable;

mod util;

#[cfg(test)]
mod test;

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
    OutdatedConstructor,
    TooLargePayload,
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
        match e {
            TxError::OutdatedConstructor => {
                io::Error::new(io::ErrorKind::Other, format!("Outdated constructor"))
            }
            TxError::TooLargePayload => {
                io::Error::new(io::ErrorKind::Other, format!("Too large payload"))
            }
            TxError::IoError(e2) => e2,
            TxError::Other(msg) => io::Error::new(io::ErrorKind::Other, format!("Other: {}", msg)),
        }
    }
}

pub type TxResult<T> = Result<T, TxError>;

fn io_result_to_tx_result(r: Option<io::Result<()>>) -> TxResult<()> {
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
    InvalidContent,
    PoisonedLock,
    Other(String),
}

pub type RxResult<T> = Result<T, RxError>;

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
        println!("VersionedTx ticked to {}", self.current_rev);
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

    pub fn send<T>(&mut self, num_packets: usize, size: usize, builder: T) -> TxResult<()>
        where T: FnMut(MutableEthernetPacket)
    {
        match self.sender {
            TxSender::Versioned(ref vtx) => {
                match vtx.lock() {
                    Ok(mut sender) => {
                        if self.rev != sender.current_rev {
                            Err(TxError::OutdatedConstructor)
                        } else {
                            Self::internal_send(&mut sender.sender, num_packets, size, builder)
                        }
                    }
                    Err(_) => Err(TxError::Other(format!("Unable to lock mutex"))),
                }
            }
            TxSender::Direct(ref mut s) => Self::internal_send(s, num_packets, size, builder),
        }
    }

    fn internal_send<T>(sender: &mut Box<EthernetDataLinkSender>,
                        num_packets: usize,
                        size: usize,
                        mut builder: T)
                        -> TxResult<()>
        where T: FnMut(MutableEthernetPacket)
    {
        let result = sender.build_and_send(num_packets, size, &mut builder);
        io_result_to_tx_result(result)
    }
}

// pub fn stack() -> io::Result<NetworkStack> {
// let icmp_factory = IcmpListenerFactory::new(); // Save to stack for
// adding listeners
//     let icmp_listener = icmp_factory.ipv4_listener();
//
//     let arp_factory = ArpFactory::new();
//     let mut ipv4_factory = Ipv4Factory::new(arp_factory, ipv4_listeners);
//
//     let mut ethernets = vec![];
//     for interface in datalink::interfaces() {
//         let ethernet = try!(create_ethernet(interface));
//         ethernets.push(ethernet);
//     }
//     Ok(NetworkStack::new(&ethernets[..]))
// }
//
// fn convert_interface(interface: NetworkInterface) -> io::Result<Interface> {
//     if let Some(mac) = interface.mac {
//         Ok(Interface {
//             name: interface.name,
//             mac: mac,
//         })
//     } else {
//         Err(io::Error::new(io::ErrorKind::Other,
//                            format!("No mac for {}", interface.name)))
//     }
// }
