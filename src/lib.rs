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

use pnet::util::NetworkInterface;

pub mod ethernet;
pub mod arp;
pub mod ipv4;
mod internal;

use internal::PnetEthernetProvider;
use ethernet::{Ethernet, EthernetProvider};
use arp::Arp;
use ipv4::Ipv4;

pub struct NetworkStackBuilder<'a> {
    config: Option<pnet::datalink::Config>,
    interfaces: Option<Vec<NetworkInterface>>,
    provider: Option<&'a mut EthernetProvider>,
}

impl<'a> NetworkStackBuilder<'a> {
    pub fn new() -> NetworkStackBuilder<'a> {
        NetworkStackBuilder {
            config: None,
            interfaces: None,
            provider: None,
        }
    }

    /// Set which interfaces this `NetworkStack` will manage.
    /// Not calling this will build a `NetworkStack` listening for all interfaces provided by
    /// the `EthernetProvider`.
    pub fn set_interfaces(&mut self, interfaces: Vec<NetworkInterface>) -> &mut Self {
        self.interfaces = Some(interfaces);
        self
    }

    /// Changes what data link provider to use to read and write raw packets from the interfaces.
    /// Not setting this will use `pnet` as the provider. Common usage of `rips` won't change
    /// this, it's mostly used by the testing tools to provide mock providers.
    pub fn set_provider(&'a mut self, provider: &'a mut EthernetProvider) -> &'a mut Self {
        self.provider = Some(provider);
        self
    }

    pub fn create(&mut self) -> io::Result<NetworkStack> {
        let config = match self.config {
            Some(c) => c,
            None => pnet::datalink::Config::default(),
        };
        let mut default_provider = PnetEthernetProvider;
        let mut provider: &mut EthernetProvider = match self.provider.as_mut() {
            Some(provider) => *provider,
            None => &mut default_provider as &mut EthernetProvider,
        };
        let interfaces = match self.interfaces.as_ref() {
            Some(interfaces) => interfaces.clone(),
            None => provider.get_network_interfaces(),
        };
        // println!("Creating stack with {:?} interfaces", interfaces);
        NetworkStack::new(&mut *provider, &interfaces[..], &config)
    }
}

/// The main struct of this library, managing an entire TCP/IP stack. Takes care of ARP,
/// routing tables, threads, TCP resends/fragmentation etc. Most of this is still unimplemented.
pub struct NetworkStack {
    ethernets: HashMap<NetworkInterface, Ethernet>,
    arps: HashMap<NetworkInterface, Arp>,
    ipv4s: HashMap<NetworkInterface, HashMap<Ipv4Addr, Ipv4>>,
}

#[allow(unused_variables)]
impl NetworkStack {
    /// Construct a `NetworkStack` with a specific datalink layer provider.
    /// You probably don't want to call this directly. Use the `NetworkStackBuilder` instead.
    pub fn new(provider: &mut EthernetProvider,
               interfaces: &[NetworkInterface],
               config: &pnet::datalink::Config)
               -> io::Result<NetworkStack> {
        let mut ethernets = HashMap::new();
        let mut arps = HashMap::new();
        for iface in interfaces {
            let ethernet = try!(Ethernet::new_with_provider(provider, &iface, config));
            ethernets.insert(iface.clone(), ethernet.clone());

            let arp = Arp::new(ethernet.clone());
            arps.insert(iface.clone(), arp.clone());
        }
        Ok(NetworkStack {
            ethernets: ethernets,
            arps: arps,
            ipv4s: HashMap::new(),
        })
    }

    /// Attach a IPv4 network to a an interface. The resulting `Ipv4` instance can be used to
    /// communicate with this network.
    pub fn add_ipv4(&mut self, iface: &NetworkInterface, conf: ipv4::Ipv4Conf) -> Option<Ipv4> {
        let eth = self.get_ethernet(iface);
        let arp = self.get_arp(iface);
        if eth.is_none() || arp.is_none() {
            return None;
        }
        let ip = conf.ip;
        let ipv4 = Ipv4::new(eth.unwrap(), arp.unwrap(), conf);
        if !self.ipv4s.contains_key(iface) {
            self.ipv4s.insert(iface.clone(), HashMap::new());
        }
        let ipv4s = self.ipv4s.get_mut(iface).unwrap();
        ipv4s.insert(ip, ipv4.clone());
        Some(ipv4)
    }

    pub fn get_ethernet(&mut self, iface: &NetworkInterface) -> Option<Ethernet> {
        self.ethernets.get(iface).map(|ethernet| ethernet.clone())
    }

    pub fn get_arp(&mut self, iface: &NetworkInterface) -> Option<Arp> {
        self.arps.get(iface).map(|arp| arp.clone())
    }

    pub fn get_ipv4(&mut self, iface: &NetworkInterface, ip: &Ipv4Addr) -> Option<Ipv4> {
        if let Some(iface_ipv4s) = self.ipv4s.get(iface) {
            if let Some(ipv4) = iface_ipv4s.get(ip) {
                return Some(ipv4.clone());
            }
        }
        None
    }
}
