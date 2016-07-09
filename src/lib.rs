//! # librips
//!
//! `librips` is a TCP/IP stack implemented in Rust.

// #![deny(missing_docs)]
#[allow(unused_imports)]

extern crate pnet;
extern crate pnet_packets;
extern crate ipnetwork;

use std::collections::HashMap;
use std::net::Ipv4Addr;

use pnet::util::MacAddr;

pub mod ethernet;
pub mod arp;
pub mod ipv4;

use ethernet::Ethernet;
use arp::Arp;
use ipv4::Ipv4;

/// The main struct of this library, managing an entire TCP/IP stack. Takes care of ARP,
/// routing tables, threads, TCP resends/fragmentation etc. Most of this is still unimplemented.
pub struct NetworkStack {
    ethernets: HashMap<MacAddr, Ethernet>,
    arps: HashMap<MacAddr, Arp>,
    ipv4s: HashMap<MacAddr, HashMap<Ipv4Addr, Ipv4>>,
}

#[allow(unused_variables)]
impl NetworkStack {
    /// Construct a `NetworkStack` with a specific datalink layer provider.
    /// You probably don't want to call this directly. Use the `NetworkStackBuilder` instead.
    pub fn new(ethernets: &[Ethernet]) -> NetworkStack {
        let mut eths = HashMap::new();
        let mut arps = HashMap::new();
        for ethernet in ethernets {
            let mac = ethernet.mac;
            eths.insert(mac, ethernet.clone());

            let arp = Arp::new(ethernet.clone());
            arps.insert(mac, arp.clone());
        }
        NetworkStack {
            ethernets: eths,
            arps: arps,
            ipv4s: HashMap::new(),
        }
    }

    /// Attach a IPv4 network to a an interface. The resulting `Ipv4` instance can be used to
    /// communicate with this network.
    pub fn add_ipv4(&mut self, mac: MacAddr, conf: ipv4::Ipv4Conf) -> Option<Ipv4> {
        let eth = self.get_ethernet(mac);
        let arp = self.get_arp(mac);
        if eth.is_none() || arp.is_none() {
            return None;
        }
        let ip = conf.ip;
        let ipv4 = Ipv4::new(eth.unwrap(), arp.unwrap(), conf);
        if !self.ipv4s.contains_key(&mac) {
            self.ipv4s.insert(mac, HashMap::new());
        }
        let ipv4s = self.ipv4s.get_mut(&mac).unwrap();
        ipv4s.insert(ip, ipv4.clone());
        Some(ipv4)
    }

    pub fn get_ethernet(&self, mac: MacAddr) -> Option<Ethernet> {
        self.ethernets.get(&mac).map(|ethernet| ethernet.clone())
    }

    pub fn get_arp(&self, mac: MacAddr) -> Option<Arp> {
        self.arps.get(&mac).map(|arp| arp.clone())
    }

    pub fn get_ipv4(&self, mac: MacAddr, ip: Ipv4Addr) -> Option<Ipv4> {
        if let Some(iface_ipv4s) = self.ipv4s.get(&mac) {
            if let Some(ipv4) = iface_ipv4s.get(&ip) {
                return Some(ipv4.clone());
            }
        }
        None
    }
}
