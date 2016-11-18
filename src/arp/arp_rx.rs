

use {RxError, RxResult, VersionedTx};
use ethernet::EthernetListener;

use pnet::packet::Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use super::TableData;

/// Receiver and parser of Arp packets. Shares table instance with the
/// `ArpTable` that created it. Upon valid incoming Arp packet the table will
/// be updated and the `VersionedTx` referenced in the struct will have its
/// revision bumped.
pub struct ArpRx {
    data: Arc<Mutex<TableData>>,
    vtx: Arc<Mutex<VersionedTx>>,
}

impl ArpRx {
    pub fn new(data: Arc<Mutex<TableData>>, vtx: Arc<Mutex<VersionedTx>>) -> Self {
        ArpRx {
            data: data,
            vtx: vtx,
        }
    }
}

impl EthernetListener for ArpRx {
    fn recv(&mut self, _time: SystemTime, pkg: &EthernetPacket) -> RxResult {
        let arp_pkg = ArpPacket::new(pkg.payload()).unwrap();
        let ip = arp_pkg.get_sender_proto_addr();
        let mac = arp_pkg.get_sender_hw_addr();
        debug!("Arp MAC: {} -> IPv4: {}", mac, ip);

        let mut data = self.data.lock().unwrap();
        let old_mac = data.table.insert(ip, mac);
        if old_mac.is_none() || old_mac != Some(mac) {
            // The new MAC is different from the old one, bump tx VersionedTx
            self.vtx.lock().unwrap().inc();
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
