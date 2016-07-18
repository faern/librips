//! # librips
//!
//! `librips` is a TCP/IP stack implemented in Rust.

// #![deny(missing_docs)]
#[allow(unused_imports)]

extern crate pnet;
extern crate ipnetwork;

use std::io;
use std::collections::HashMap;
use std::net::Ipv4Addr;

use pnet::datalink::{self, NetworkInterface};
use pnet::util::MacAddr;
use pnet::packet::ip::IpNextHeaderProtocols;

pub mod ethernet;

/// Module for everything related to the Arp protocol
pub mod arp;

/// Module for all IPv4 functionality
pub mod ipv4;

/// Module for Icmp functionality
pub mod icmp;

pub mod routing;

mod test;

//mod util;

use ethernet::{Ethernet, EthernetListener};
use arp::{Arp, ArpFactory};
use ipv4::{Ipv4, Ipv4Config, Ipv4Factory};
use icmp::IcmpListenerFactory;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Interface {
    pub name: String,
    pub mac: MacAddr,
}

pub struct EthernetChannel(pub Box<datalink::EthernetDataLinkSender>,
                           pub Box<datalink::EthernetDataLinkReceiver>);

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

fn create_ethernet(interface: NetworkInterface,
                   listeners: Vec<Box<EthernetListener>>)
                   -> io::Result<Ethernet> {
    let config = datalink::Config::default();
    let channel = match try!(datalink::channel(&interface, config)) {
        datalink::Channel::Ethernet(tx, rx) => EthernetChannel(tx, rx),
        _ => panic!("Invalid channel type returned"),
    };
    let internal_interface = try!(convert_interface(interface));
    Ok(Ethernet::new(internal_interface, channel, listeners))
}

fn convert_interface(interface: NetworkInterface) -> io::Result<Interface> {
    if let Some(mac) = interface.mac {
        Ok(Interface {
            name: interface.name,
            mac: mac,
        })
    } else {
        Err(io::Error::new(io::ErrorKind::Other,
                           format!("No mac for {}", interface.name)))
    }
}

struct StackInterface {
    ethernet: Ethernet,
    arp: Arp,
    ipv4s: HashMap<Ipv4Addr, Ipv4Config>,
}

/// The main struct of this library, managing an entire TCP/IP stack. Takes
/// care of ARP, routing tables, threads, TCP resends/fragmentation etc. Most
/// of this is still unimplemented.
pub struct NetworkStack {
    interfaces: HashMap<Interface, StackInterface>,
}

impl NetworkStack {
    pub fn new() -> NetworkStack {
        NetworkStack { interfaces: HashMap::new() }
    }

    pub fn add_ethernet(&mut self,
                        interface: Interface,
                        channel: EthernetChannel)
                        -> Result<(), ()> {
        if self.interfaces.contains_key(&interface) {
            Err(())
        } else {
            let icmp_factory = IcmpListenerFactory::new();
            let icmp_listener = icmp_factory.ipv4_listener();

            let mut ipv4_listeners = HashMap::new();
            ipv4_listeners.insert(IpNextHeaderProtocols::Icmp, icmp_listener);

            let arp_factory = ArpFactory::new();
            let arp_listener = arp_factory.listener();

            let mut ipv4_factory = Ipv4Factory::new(arp_factory, ipv4_listeners);
            let ipv4_listener = ipv4_factory.listener().unwrap();

            let ethernet_listeners = vec![arp_listener, ipv4_listener];

            let ethernet = Ethernet::new(interface.clone(), channel, ethernet_listeners);
            let arp = ipv4_factory.arp_factory().arp(ethernet.clone());
            let stack_interface = StackInterface {
                ethernet: ethernet,
                arp: arp,
                ipv4s: HashMap::new(),
            };
            self.interfaces.insert(interface.clone(), stack_interface);
            Ok(())
        }
    }

    /// Attach a IPv4 network to a an interface. The resulting `Ipv4`
    /// can be used to communicate with this network.
    pub fn add_ipv4(&mut self, interface: &Interface, config: ipv4::Ipv4Config) -> Result<(), ()> {
        if let Some(stack_interface) = self.interfaces.get_mut(interface) {
            let ipv4s = &mut stack_interface.ipv4s;
            let ip = config.ip;
            if ipv4s.contains_key(&ip) {
                Err(())
            } else {
                ipv4s.insert(ip, config);
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    pub fn get_ethernet(&self, interface: &Interface) -> Option<Ethernet> {
        self.interfaces.get(interface).map(|si| si.ethernet.clone())
    }

    pub fn get_arp(&self, interface: &Interface) -> Option<Arp> {
        self.interfaces.get(interface).map(|si| si.arp.clone())
    }
}
