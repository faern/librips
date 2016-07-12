//! # librips
//!
//! `librips` is a TCP/IP stack implemented in Rust.

// #![deny(missing_docs)]
#[allow(unused_imports)]

extern crate pnet;
extern crate pnet_packets;
extern crate ipnetwork;

use std::io;
use std::collections::HashMap;
use std::net::Ipv4Addr;

use pnet::datalink::{self, NetworkInterface};
use pnet::util::MacAddr;

pub mod ethernet;

/// Module for everything related to the Arp protocol
pub mod arp;

// /// Module for all IPv4 functionality
// pub mod ipv4;

// /// Module for Icmp functionality
// pub mod icmp;

// use ethernet::Ethernet;
// use arp::Arp;
// use ipv4::Ipv4;
//
// /// The main struct of this library, managing an entire TCP/IP stack. Takes
// /// care of ARP, routing tables, threads, TCP resends/fragmentation etc. Most
// /// of this is still unimplemented.
// pub struct NetworkStack {
//     ethernets: HashMap<MacAddr, Ethernet>,
//     arps: HashMap<MacAddr, Arp>,
//     ipv4s: HashMap<MacAddr, HashMap<Ipv4Addr, Ipv4>>,
// }
//
// /// Create a `NetworkStack` managing all available interfaces using the default
// /// pnet backend. This stack will have ethernet and arp management set up
// /// internally, but no IPs or anything.
// pub fn stack() -> io::Result<NetworkStack> {
//     let mut ethernets = vec![];
//     for interface in datalink::interfaces() {
//         let ethernet = try!(create_ethernet(interface));
//         ethernets.push(ethernet);
//     }
//     Ok(NetworkStack::new(&ethernets[..]))
// }
//
// fn create_ethernet(interface: NetworkInterface) -> io::Result<Ethernet> {
//     let mac = match interface.mac {
//         Some(mac) => mac,
//         None => {
//             return Err(io::Error::new(io::ErrorKind::Other,
//                                       format!("No mac for {}", interface.name)))
//         }
//     };
//     let config = datalink::Config::default();
//     let channel = try!(datalink::channel(&interface, config));
//     Ok(Ethernet::new(mac, channel))
// }
//
// #[allow(unused_variables)]
// impl NetworkStack {
//     /// Construct a `NetworkStack` managing a given set of `Ethernet`
//     /// interfaces.
//     /// The stack will set up an `Arp` for each interface automatically
//     /// internally.
//     pub fn new(ethernets: &[Ethernet]) -> NetworkStack {
//         let mut eths = HashMap::new();
//         let mut arps = HashMap::new();
//         for ethernet in ethernets {
//             let mac = ethernet.mac;
//             eths.insert(mac, ethernet.clone());
//
//             let arp = Arp::new(ethernet.clone());
//             arps.insert(mac, arp.clone());
//         }
//         NetworkStack {
//             ethernets: eths,
//             arps: arps,
//             ipv4s: HashMap::new(),
//         }
//     }
//
//     /// Attach a IPv4 network to a an interface. The resulting `Ipv4` instance
//     /// can be used to
//     /// communicate with this network.
//     pub fn add_ipv4(&mut self, mac: MacAddr, conf: ipv4::Ipv4Config) -> Option<Ipv4> {
//         let eth = self.get_ethernet(mac);
//         let arp = self.get_arp(mac);
//         if eth.is_none() || arp.is_none() {
//             return None;
//         }
//         let ip = conf.ip;
//         let ipv4 = Ipv4::new(eth.unwrap(), arp.unwrap(), conf);
//         if !self.ipv4s.contains_key(&mac) {
//             self.ipv4s.insert(mac, HashMap::new());
//         }
//         let ipv4s = self.ipv4s.get_mut(&mac).unwrap();
//         ipv4s.insert(ip, ipv4.clone());
//         Some(ipv4)
//     }
//
//     /// dead
//     pub fn get_ethernet(&self, mac: MacAddr) -> Option<Ethernet> {
//         self.ethernets.get(&mac).map(|ethernet| ethernet.clone())
//     }
//
//     /// dead
//     pub fn get_arp(&self, mac: MacAddr) -> Option<Arp> {
//         self.arps.get(&mac).map(|arp| arp.clone())
//     }
//
//     /// dead
//     pub fn get_ipv4(&self, mac: MacAddr, ip: Ipv4Addr) -> Option<Ipv4> {
//         if let Some(iface_ipv4s) = self.ipv4s.get(&mac) {
//             if let Some(ipv4) = iface_ipv4s.get(&ip) {
//                 return Some(ipv4.clone());
//             }
//         }
//         None
//     }
// }
