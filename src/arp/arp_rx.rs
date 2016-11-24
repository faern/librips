

use {RxResult, StackInterfaceMsg};
use ethernet::EthernetListener;

use pnet::packet::Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};

use std::sync::mpsc::Sender;
use std::time::SystemTime;

pub struct ArpRx {
    listener: Sender<StackInterfaceMsg>,
}

impl ArpRx {
    pub fn new(listener: Sender<StackInterfaceMsg>) -> Self {
        ArpRx {
            listener: listener,
        }
    }
}

impl EthernetListener for ArpRx {
    fn recv(&mut self, _time: SystemTime, pkg: &EthernetPacket) -> RxResult {
        let arp_pkg = ArpPacket::new(pkg.payload()).unwrap();
        let ip = arp_pkg.get_sender_proto_addr();
        let mac = arp_pkg.get_sender_hw_addr();
        debug!("Arp MAC: {} -> IPv4: {}", mac, ip);

        self.listener.send(StackInterfaceMsg::UpdateArpTable(ip, mac)).unwrap();
        Ok(())
    }

    fn get_ethertype(&self) -> EtherType {
        EtherTypes::Arp
    }
}
