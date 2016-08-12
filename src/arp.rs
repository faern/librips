#[allow(unused_imports)]

use std::io;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::net::Ipv4Addr;
use std::time::SystemTime;

use pnet::util::MacAddr;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::Packet;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};

use {TxError, TxResult, RxResult, RxError, VersionedTx};
use ethernet::{EthernetListener, EthernetTx};

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

    pub fn listener(&self, vtx: Arc<Mutex<VersionedTx>>) -> Box<EthernetListener> {
        Box::new(ArpRx {
            table: self.table.clone(),
            listeners: self.listeners.clone(),
            vtx: vtx,
        }) as Box<EthernetListener>
    }

    pub fn arp_tx(&self, ethernet: EthernetTx) -> ArpTx {
        assert_eq!(ethernet.dst,
                   MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
        ArpTx {
            table: self.table.clone(),
            ethernet: ethernet,
            listeners: self.listeners.clone(),
        }
    }
}

pub struct ArpRx {
    table: Arc<RwLock<HashMap<Ipv4Addr, MacAddr>>>,
    listeners: Arc<Mutex<HashMap<Ipv4Addr, Vec<Sender<MacAddr>>>>>,
    vtx: Arc<Mutex<VersionedTx>>,
}

impl EthernetListener for ArpRx {
    fn recv(&mut self, _time: SystemTime, pkg: &EthernetPacket) -> RxResult {
        let arp_pkg = ArpPacket::new(pkg.payload()).unwrap();
        let ip = arp_pkg.get_sender_proto_addr();
        let mac = arp_pkg.get_sender_hw_addr();
        println!("Arp MAC: {} -> IPv4: {}", mac, ip);
        let mut table = try!(self.table.write().or(Err(RxError::PoisonedLock)));
        let old_mac = table.insert(ip, mac);
        if old_mac.is_none() || old_mac != Some(mac) {
            // The new MAC is different from the old one, bump tx VersionedTx
            try!(self.vtx.lock().or(Err(RxError::PoisonedLock))).inc();
        }
        let listeners = try!(self.listeners.lock().or(Err(RxError::PoisonedLock)));
        if let Some(ip_listeners) = listeners.get(&ip) {
            for listener in ip_listeners {
                listener.send(mac).unwrap_or(());
            }
        }
        Ok(())
    }

    fn get_ethertype(&self) -> EtherType {
        EtherTypes::Arp
    }
}

/// An Arp table and query interface struct.
pub struct ArpTx {
    table: Arc<RwLock<HashMap<Ipv4Addr, MacAddr>>>,
    ethernet: EthernetTx,
    listeners: Arc<Mutex<HashMap<Ipv4Addr, Vec<Sender<MacAddr>>>>>,
}

impl ArpTx {
    /// Queries the table for a MAC. If it does not exist a request is sent and
    /// the call is blocked
    /// until a reply has arrived
    pub fn get(&mut self, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> TxResult<MacAddr> {
        let mac_rx = {
            let table_arc = self.table.clone(); // Must do this to not borrow self
            let table = try!(table_arc.read()
                .map_err(|_| TxError::Other(format!("Unable to lock mutex"))));
            if let Some(mac) = table.get(&target_ip) {
                return Ok(mac.clone());
            }
            let rx = self.add_listener(target_ip);
            self.send(sender_ip, target_ip).expect("Network send error");
            rx
        }; // Release table lock
        mac_rx.recv().map_err(|_| TxError::Other(format!("Unable to read MAC from mac_rx")))
    }

    /// Sends an Arp packet to the network. More specifically Ipv4 to Ethernet
    /// request
    pub fn send(&mut self, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> TxResult<()> {
        let local_mac = self.ethernet.src;
        let mut builder_wrapper = |payload: &mut [u8]| {
            let mut arp_pkg = MutableArpPacket::new(payload).unwrap();
            arp_pkg.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_pkg.set_protocol_type(EtherTypes::Ipv4);
            arp_pkg.set_hw_addr_len(6);
            arp_pkg.set_proto_addr_len(4);
            arp_pkg.set_operation(ArpOperations::Request);
            arp_pkg.set_sender_hw_addr(local_mac);
            arp_pkg.set_sender_proto_addr(sender_ip);
            arp_pkg.set_target_hw_addr(MacAddr::new(0, 0, 0, 0, 0, 0));
            arp_pkg.set_target_proto_addr(target_ip);
        };
        self.ethernet.send(1,
                           ArpPacket::minimum_packet_size(),
                           EtherTypes::Arp,
                           &mut builder_wrapper)
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
    // TODO: This should also invalidate the Tx
    pub fn insert(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        let mut table = self.table.write().expect("Unable to lock Arp::table for writing");
        table.insert(ip, mac);
    }
}
