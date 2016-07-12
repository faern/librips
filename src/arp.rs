#[allow(unused_imports)]

use std::io;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::net::Ipv4Addr;

use pnet::util::MacAddr;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperation, ArpOperations, ArpPacket, MutableArpPacket};

use ethernet::{Ethernet, EthernetListener};

pub struct ArpFactory {
    table: Arc<RwLock<HashMap<Ipv4Addr, MacAddr>>>,
    listeners: Arc<Mutex<HashMap<Ipv4Addr, Vec<Sender<MacAddr>>>>>,
}

impl ArpFactory {
    pub fn new() -> ArpFactory {
        ArpFactory {
            table: Arc::new(RwLock::new(HashMap::new())),
            listeners: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn listener(&self) -> ArpEthernetListener {
        ArpEthernetListener {
            table: self.table.clone(),
            listeners: self.listeners.clone(),
        }
    }

    pub fn arp(&self, ethernet: Ethernet) -> Arp {
        Arp {
            table: self.table.clone(),
            ethernet: ethernet,
            listeners: self.listeners.clone(),
        }
    }
}

#[derive(Clone)]
pub struct ArpEthernetListener {
    table: Arc<RwLock<HashMap<Ipv4Addr, MacAddr>>>,
    listeners: Arc<Mutex<HashMap<Ipv4Addr, Vec<Sender<MacAddr>>>>>,
}

impl EthernetListener for ArpEthernetListener {
    fn recv(&mut self, pkg: EthernetPacket) {
        let arp_pkg = ArpPacket::new(pkg.payload()).unwrap();
        let ip = arp_pkg.get_sender_proto_addr();
        let mac = arp_pkg.get_sender_hw_addr();
        println!("Arp MAC: {} -> IPv4: {}", mac, ip);
        let mut table =
            self.table.write().expect("Unable to lock ArpEthernetListener::table for writing");
        table.insert(ip, mac);
        let listeners =
            self.listeners.lock().expect("Unable to lock ArpEthernetListener::listeners");
        if let Some(ip_listeners) = listeners.get(&ip) {
            for listener in ip_listeners {
                listener.send(mac).expect("Unable to send MAC to listener");
            }
        }
    }
}

/// An Arp table and query interface struct.
#[derive(Clone)]
pub struct Arp {
    table: Arc<RwLock<HashMap<Ipv4Addr, MacAddr>>>,
    ethernet: Ethernet,
    listeners: Arc<Mutex<HashMap<Ipv4Addr, Vec<Sender<MacAddr>>>>>,
}

impl Arp {
    pub fn new(ethernet: Ethernet) -> Arp {
        Arp {
            table: Arc::new(RwLock::new(HashMap::new())),
            ethernet: ethernet,
            listeners: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Arp {
    /// Queries the table for a MAC. If it does not exist a request is sent and
    /// the call is blocked
    /// until a reply has arrived
    // TODO: Rewrite with match on table.get and a drop(table)
    pub fn get(&mut self, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> MacAddr {
        let mac_rx = {
            let table_arc = self.table.clone(); // Must do this to not borrow self
            let table = table_arc.read().expect("Unable to lock Arp::table for reading");
            if let Some(mac) = table.get(&target_ip) {
                return mac.clone();
            }
            let rx = self.add_listener(target_ip);
            self.send(sender_ip, target_ip)
                .expect("Too small buffer")
                .expect("Network send error");
            rx
        }; // Release table lock
        mac_rx.recv().expect("Unable to read MAC from mac_rx")
    }

    /// Sends an Arp packet to the network. More specifically Ipv4 to Ethernet
    /// request
    pub fn send(&mut self, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Option<io::Result<()>> {
        let local_mac = self.ethernet.mac;
        let mut builder_wrapper = |eth_pkg: &mut MutableEthernetPacket| {
            eth_pkg.set_destination(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
            eth_pkg.set_ethertype(EtherTypes::Arp);
            {
                let mut arp_pkg = MutableArpPacket::new(eth_pkg.payload_mut()).unwrap();
                arp_pkg.set_hardware_type(ArpHardwareTypes::Ethernet);
                arp_pkg.set_protocol_type(EtherTypes::Ipv4);
                arp_pkg.set_hw_addr_len(6);
                arp_pkg.set_proto_addr_len(4);
                arp_pkg.set_operation(ArpOperations::Request);
                arp_pkg.set_sender_hw_addr(local_mac.clone());
                arp_pkg.set_sender_proto_addr(sender_ip.clone());
                arp_pkg.set_target_hw_addr(MacAddr::new(0, 0, 0, 0, 0, 0));
                arp_pkg.set_target_proto_addr(target_ip.clone());
            }
        };
        self.ethernet.send(1, ArpPacket::minimum_packet_size(), &mut builder_wrapper)
    }

    fn add_listener(&mut self, ip: Ipv4Addr) -> Receiver<MacAddr> {
        let (tx, rx) = channel();
        let mut listeners = self.listeners.lock().expect("Unable to lock Arp::listeners");
        if !listeners.contains_key(&ip) {
            listeners.insert(ip, vec![tx]);
        } else {
            listeners.get_mut(&ip).unwrap().push(tx);
        }
        rx
    }

    /// Manually insert an IP -> MAC mapping into this Arp table
    pub fn insert(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        let mut table = self.table.write().expect("Unable to lock Arp::table for writing");
        table.insert(ip, mac);
    }
}
