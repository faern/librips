use {RxResult, RxError};
use ethernet::EthernetListener;

use pnet::packet::Packet;
use pnet::packet::arp::{ArpPacket, ArpOperations};
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use stack::StackInterfaceMsg;

use std::sync::mpsc::Sender;
use std::time::SystemTime;

pub struct ArpRx {
    listener: Sender<StackInterfaceMsg>,
}

impl ArpRx {
    pub fn new(listener: Sender<StackInterfaceMsg>) -> Self {
        ArpRx { listener: listener }
    }

    fn handle_request(&mut self, arp_pkg: &ArpPacket) -> RxResult {
        let sender_mac = arp_pkg.get_sender_hw_addr();
        let sender_ip = arp_pkg.get_sender_proto_addr();
        let target_ip = arp_pkg.get_target_proto_addr();
        self.listener
            .send(StackInterfaceMsg::ArpRequest(sender_ip, sender_mac, target_ip))
            .unwrap();
        Ok(())
    }

    fn handle_reply(&mut self, arp_pkg: &ArpPacket) -> RxResult {
        let sender_mac = arp_pkg.get_sender_hw_addr();
        let sender_ip = arp_pkg.get_sender_proto_addr();
        debug!("Arp reply. MAC: {} -> IPv4: {}", sender_mac, sender_ip);
        self.listener.send(StackInterfaceMsg::UpdateArpTable(sender_ip, sender_mac)).unwrap();
        Ok(())
    }
}

impl EthernetListener for ArpRx {
    fn recv(&mut self, _time: SystemTime, pkg: &EthernetPacket) -> RxResult {
        let arp_pkg = ArpPacket::new(pkg.payload()).unwrap();
        // TODO: Check all other fields so they are correct.
        match arp_pkg.get_operation() {
            ArpOperations::Request => self.handle_request(&arp_pkg),
            ArpOperations::Reply => self.handle_reply(&arp_pkg),
            _ => Err(RxError::InvalidContent),
        }
    }

    fn get_ethertype(&self) -> EtherType {
        EtherTypes::Arp
    }
}
