use {Payload, TxResult};
use ethernet::{EthernetPayload, EthernetTx};

use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpOperation, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherType, EtherTypes};
use pnet::util::MacAddr;

use std::net::Ipv4Addr;

pub struct ArpRequestTx<T: EthernetTx> {
    ethernet: T,
}

impl<T: EthernetTx> ArpRequestTx<T> {
    pub fn new(ethernet: T) -> Self {
        ArpRequestTx { ethernet: ethernet }
    }

    /// Sends an Arp request packet to the network. More specifically Ipv4 to
    /// Ethernet request
    pub fn send(&mut self, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> TxResult {
        let builder = ArpBuilder::new_request(self.ethernet.src(), sender_ip, target_ip);
        self.ethernet.send(1, ArpPacket::minimum_packet_size(), builder)
    }
}

pub struct ArpReplyTx<T: EthernetTx> {
    ethernet: T,
}

impl<T: EthernetTx> ArpReplyTx<T> {
    pub fn new(ethernet: T) -> Self {
        ArpReplyTx { ethernet: ethernet }
    }

    pub fn send(&mut self,
                sender_ip: Ipv4Addr,
                target_mac: MacAddr,
                target_ip: Ipv4Addr)
                -> TxResult {
        let builder = ArpBuilder::new_reply(self.ethernet.src(), sender_ip, target_mac, target_ip);
        self.ethernet.send(1, ArpPacket::minimum_packet_size(), builder)
    }
}

pub struct ArpBuilder {
    operation: ArpOperation,
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
}

impl ArpBuilder {
    /// Constructs a new `ArpBuilder` able to construct Arp packets
    pub fn new_request(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Self {
        ArpBuilder {
            operation: ArpOperations::Request,
            sender_mac: sender_mac,
            sender_ip: sender_ip,
            target_mac: MacAddr::new(0, 0, 0, 0, 0, 0),
            target_ip: target_ip,
        }
    }

    pub fn new_reply(sender_mac: MacAddr,
                     sender_ip: Ipv4Addr,
                     target_mac: MacAddr,
                     target_ip: Ipv4Addr)
                     -> Self {
        ArpBuilder {
            operation: ArpOperations::Reply,
            sender_mac: sender_mac,
            sender_ip: sender_ip,
            target_mac: target_mac,
            target_ip: target_ip,
        }
    }
}

impl EthernetPayload for ArpBuilder {
    fn ether_type(&self) -> EtherType {
        EtherTypes::Arp
    }
}

impl Payload for ArpBuilder {
    fn len(&self) -> usize {
        ArpPacket::minimum_packet_size()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        let mut arp_pkg = MutableArpPacket::new(buffer).unwrap();
        arp_pkg.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_pkg.set_protocol_type(EtherTypes::Ipv4);
        arp_pkg.set_hw_addr_len(6);
        arp_pkg.set_proto_addr_len(4);
        arp_pkg.set_operation(self.operation);
        arp_pkg.set_sender_hw_addr(self.sender_mac);
        arp_pkg.set_sender_proto_addr(self.sender_ip);
        arp_pkg.set_target_hw_addr(self.target_mac);
        arp_pkg.set_target_proto_addr(self.target_ip);
    }
}
