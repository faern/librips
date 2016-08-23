#[allow(unused_imports)]

use std::io;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::net::Ipv4Addr;
use std::time::SystemTime;

use pnet::util::MacAddr;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::Packet;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};

use {TxResult, RxResult, RxError, VersionedTx};
use ethernet::{EthernetListener, EthernetTx};

struct TableData {
    table: HashMap<Ipv4Addr, MacAddr>,
    listeners: HashMap<Ipv4Addr, Vec<Sender<MacAddr>>>,
}

#[derive(Clone)]
pub struct ArpTable {
    data: Arc<Mutex<TableData>>,
}

impl ArpTable {
    pub fn new() -> ArpTable {
        let data = Arc::new(Mutex::new(TableData {
            table: HashMap::new(),
            listeners: HashMap::new(),
        }));
        ArpTable {
            data: data,
        }
    }

    pub fn arp_rx(&self, vtx: Arc<Mutex<VersionedTx>>) -> Box<EthernetListener> {
        Box::new(ArpRx {
            data: self.data.clone(),
            vtx: vtx,
        }) as Box<EthernetListener>
    }

    /// Queries the table for a MAC. If it does not exist a request is sent and
    /// the call is blocked
    /// until a reply has arrived
    pub fn get(&mut self, target_ip: Ipv4Addr) -> Result<MacAddr, Receiver<MacAddr>> {
        let mut data = self.data.lock().unwrap();
        if let Some(mac) = data.table.get(&target_ip) {
            return Ok(*mac);
        }
        Err(Self::add_listener(&mut data, target_ip))
    }

    /// Manually insert an IP -> MAC mapping into this Arp table
    // TODO: This should also invalidate the Tx
    pub fn insert(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        let mut data = self.data.lock().expect("Unable to lock Arp::table for writing");
        data.table.insert(ip, mac);
    }

    fn add_listener(data: &mut TableData, ip: Ipv4Addr) -> Receiver<MacAddr> {
        let (tx, rx) = channel();
        if !data.listeners.contains_key(&ip) {
            data.listeners.insert(ip, vec![tx]);
        } else {
            data.listeners.get_mut(&ip).unwrap().push(tx);
        }
        rx
    }
}

pub struct ArpRx {
    data: Arc<Mutex<TableData>>,
    vtx: Arc<Mutex<VersionedTx>>,
}

impl EthernetListener for ArpRx {
    fn recv(&mut self, _time: SystemTime, pkg: &EthernetPacket) -> RxResult {
        let arp_pkg = ArpPacket::new(pkg.payload()).unwrap();
        let ip = arp_pkg.get_sender_proto_addr();
        let mac = arp_pkg.get_sender_hw_addr();
        debug!("Arp MAC: {} -> IPv4: {}", mac, ip);

        let mut data = try!(self.data.lock().or(Err(RxError::PoisonedLock)));
        let old_mac = data.table.insert(ip, mac);
        if old_mac.is_none() || old_mac != Some(mac) {
            // The new MAC is different from the old one, bump tx VersionedTx
            try!(self.vtx.lock().or(Err(RxError::PoisonedLock))).inc();
        }
        if let Some(listeners) = data.listeners.remove(&ip) {
            for listener in listeners {
                listener.send(mac).unwrap_or(());
            }
        }
        Ok(())
    }

    fn get_ethertype(&self) -> EtherType {
        EtherTypes::Arp
    }
}

pub struct ArpTx {
    ethernet: EthernetTx,
}

impl ArpTx {
    pub fn new(ethernet: EthernetTx) -> ArpTx {
        ArpTx {
            ethernet: ethernet,
        }
    }

    /// Sends an Arp packet to the network. More specifically Ipv4 to Ethernet
    /// request
    pub fn send(&mut self, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> TxResult {
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
}
