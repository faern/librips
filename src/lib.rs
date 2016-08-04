//! # librips
//!
//! `librips` is a TCP/IP stack implemented in Rust.

// #![deny(missing_docs)]
#[allow(unused_imports)]

extern crate pnet;
extern crate ipnetwork;

use std::io;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};

use pnet::datalink;
use pnet::util::MacAddr;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::datalink::EthernetDataLinkSender;

pub mod ethernet;

/// Module for everything related to the Arp protocol
pub mod arp;

/// Module for all IPv4 functionality
pub mod ipv4;

/// Module for Icmp functionality
//pub mod icmp;

//pub mod udp;

pub mod routing;

mod util;

#[cfg(test)]
mod test;

use ethernet::{EthernetRx, EthernetTx};
use arp::{Arp, ArpFactory};
use ipv4::{Ipv4Config, Ipv4EthernetListener, Ipv4Listener};
use routing::RoutingTable;

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
    MutexError,
    InsufficientBuffer,
    IoError(io::Error),
}

impl From<io::Error> for TxError {
    fn from(e: io::Error) -> Self {
        TxError::IoError(e)
    }
}

impl From<TxError> for io::Error {
    fn from(e: TxError) -> Self {
        match e {
            TxError::OutdatedConstructor => io::Error::new(io::ErrorKind::Other, format!("Outdated constructor")),
            TxError::MutexError => io::Error::new(io::ErrorKind::Other, format!("Poisoned mutex")),
            TxError::InsufficientBuffer => io::Error::new(io::ErrorKind::Other, format!("Insufficient buffer")),
            TxError::IoError(e2) => e2,
        }
    }
}

pub type TxResult = Result<(), TxError>;

fn io_result_to_tx_result(r: Option<io::Result<()>>) -> TxResult {
    match r {
        None => Err(TxError::InsufficientBuffer),
        Some(ior) => match ior {
            Err(e) => Err(TxError::from(e)),
            Ok(()) => Ok(())
        }
    }
}

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

    pub fn send<T>(&mut self,
                   num_packets: usize,
                   size: usize,
                   builder: T)
                   -> TxResult
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
                    },
                    Err(_) => Err(TxError::MutexError),
                }
            },
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

/// Create a `NetworkStack` managing all available interfaces using the default
/// pnet backend.
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
// fn create_ethernet(interface: NetworkInterface,
//                    listeners: Vec<Box<EthernetListener>>)
//                    -> io::Result<Ethernet> {
//     let config = datalink::Config::default();
//     let channel = match try!(datalink::channel(&interface, config)) {
//         datalink::Channel::Ethernet(tx, rx) => EthernetChannel(tx, rx),
//         _ => panic!("Invalid channel type returned"),
//     };
//     let internal_interface = try!(convert_interface(interface));
//     Ok(Ethernet::new(internal_interface, channel, listeners))
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

/// Represents the stack on one physical interface.
/// The larger `NetworkStack` comprises multiple of these.
struct StackInterface {
    interface: Interface,
    tx: Arc<Mutex<VersionedTx>>,
    _arp_factory: ArpFactory,
    ipv4s: HashMap<Ipv4Addr, Ipv4Config>,
    // ipv6s: HashMap<Ipv6Addr, Ipv6Config>,
    ipv4_listeners: Arc<Mutex<ipv4::IpListenerLookup>>,
    // ipv6_listeners...
    //udp_listeners: HashMap<Ipv4Addr, Arc<Mutex<udp::UdpListenerLookup>>>,
}

impl StackInterface {
    fn tx(&self) -> Tx {
        Tx::versioned(self.tx.clone())
    }

    pub fn ethernet_tx(&self, dst: MacAddr) -> EthernetTx {
        EthernetTx::new(self.tx(), self.interface.mac, dst)
    }

    pub fn add_ipv4(&mut self, config: Ipv4Config) -> Result<(), ()> {
        let ip = config.ip;
        if !self.ipv4s.contains_key(&ip) {
            self.ipv4s.insert(ip, config);
            let ipv4_listeners = self.create_ipv4_listeners(ip);
            let mut iface_ipv4_listeners = self.ipv4_listeners.lock().unwrap();
            iface_ipv4_listeners.insert(ip, ipv4_listeners);
            Ok(())
        } else {
            Err(())
        }
    }

    fn create_ipv4_listeners(&mut self,
                             ip: Ipv4Addr)
                             -> HashMap<IpNextHeaderProtocol, Box<Ipv4Listener>> {
        let mut proto_listeners = HashMap::new();
        //
        // let udp_listeners = Arc::new(Mutex::new(HashMap::new()));
        // self.udp_listeners.insert(ip, udp_listeners.clone());
        // let udp_ipv4_listener =
        //     Box::new(udp::UdpIpv4Listener::new(udp_listeners)) as Box<Ipv4Listener>;
        // proto_listeners.insert(IpNextHeaderProtocols::Udp, udp_ipv4_listener);

        // Insert Icmp listener stuff

        proto_listeners
    }
}

/// The main struct of this library, managing an entire TCP/IP stack. Takes
/// care of ARP, routing tables, threads, TCP resends/fragmentation etc. Most
/// of this is still unimplemented.
pub struct NetworkStack {
    interfaces: HashMap<Interface, StackInterface>,
    _routing_table: RoutingTable,
}

impl NetworkStack {
    pub fn new() -> NetworkStack {
        NetworkStack {
            interfaces: HashMap::new(),
            _routing_table: RoutingTable::new(),
        }
    }

    pub fn add_channel(&mut self,
                       interface: Interface,
                       channel: EthernetChannel)
                       -> Result<(), ()>
    {
        if self.interfaces.contains_key(&interface) {
            Err(())
        } else {
            let sender = channel.0;
            let receiver = channel.1;

            let vtx = Arc::new(Mutex::new(VersionedTx::new(sender)));

            let arp_factory = ArpFactory::new();
            let arp_ethernet_listener = arp_factory.listener(vtx.clone());

            let ipv4_listeners = Arc::new(Mutex::new(HashMap::new()));
            let ipv4_ethernet_listener = Ipv4EthernetListener::new(ipv4_listeners.clone());

            let ethernet_listeners = vec![arp_ethernet_listener, ipv4_ethernet_listener];
            EthernetRx::new(ethernet_listeners).spawn(receiver);

            let stack_interface = StackInterface {
                interface: interface.clone(),
                tx: vtx,
                _arp_factory: arp_factory,
                ipv4s: HashMap::new(),
                ipv4_listeners: ipv4_listeners,
                //udp_listeners: HashMap::new(),
            };
            self.interfaces.insert(interface.clone(), stack_interface);
            Ok(())
        }
    }

    pub fn ethernet_tx(&self, interface: &Interface, dst: MacAddr) -> Option<EthernetTx> {
        self.interfaces.get(interface).map(|si| si.ethernet_tx(dst))
    }

    /// Attach a IPv4 network to a an interface.
    pub fn add_ipv4(&mut self, interface: &Interface, config: Ipv4Config) -> Result<(), ()> {
        if let Some(stack_interface) = self.interfaces.get_mut(interface) {
            stack_interface.add_ipv4(config)
        } else {
            Err(())
        }
    }

    // pub fn udp_listen<A, L>(&mut self, addr: A, listener: L) -> io::Result<()>
    //     where A: ToSocketAddrs,
    //           L: udp::UdpListener + 'static
    // {
    //     match try!(util::first_socket_addr(addr)) {
    //         SocketAddr::V4(addr) => {
    //             let local_ip = addr.ip();
    //             let local_port = addr.port();
    //             if local_ip == &Ipv4Addr::new(0, 0, 0, 0) {
    //                 panic!("Rips does not support listening to all interfaces yet");
    //             } else {
    //                 for stack_interface in self.interfaces.values() {
    //                     if let Some(udp_listeners) = stack_interface.udp_listeners.get(local_ip) {
    //                         let mut udp_listeners = udp_listeners.lock().unwrap();
    //                         if !udp_listeners.contains_key(&local_port) {
    //                             udp_listeners.insert(local_port, Box::new(listener));
    //                             return Ok(());
    //                         } else {
    //                             return Err(io::Error::new(io::ErrorKind::AddrInUse,
    //                                                       format!("Address/Port is already \
    //                                                                occupied")));
    //                         }
    //                     }
    //                 }
    //                 return Err(io::Error::new(io::ErrorKind::InvalidInput,
    //                                           format!("Bind address does not exist in stack")));
    //             }
    //         },
    //         SocketAddr::V6(_) => {
    //             Err(io::Error::new(io::ErrorKind::InvalidInput, format!("Rips does not support IPv6 yet")))
    //         }
    //     }
    // }
}
