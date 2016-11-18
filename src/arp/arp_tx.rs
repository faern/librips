use {Protocol, TxResult};
use ethernet::{EthernetProtocol, EthernetTx};

use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherType, EtherTypes};
use pnet::util::MacAddr;

use std::net::Ipv4Addr;

/// Arp packet building and sending struct.
pub struct ArpTx<T: EthernetTx> {
    ethernet: T,
}

impl<T: EthernetTx> ArpTx<T> {
    /// Creates a new `ArpTx` that will transmit through `ethernet`
    pub fn new(ethernet: T) -> Self {
        ArpTx { ethernet: ethernet }
    }

    /// Sends an Arp packet to the network. More specifically Ipv4 to Ethernet
    /// request
    pub fn send(&mut self, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> TxResult {
        let builder = ArpBuilder::new(self.ethernet.src(), sender_ip, target_ip);
        self.ethernet.send(1, ArpPacket::minimum_packet_size(), builder)
    }
}

pub struct ArpBuilder {
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
}

impl ArpBuilder {
    /// Constructs a new `ArpBuilder` able to construct Arp packets
    pub fn new(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Self {
        ArpBuilder {
            sender_mac: sender_mac,
            sender_ip: sender_ip,
            target_ip: target_ip,
        }
    }
}

impl EthernetProtocol for ArpBuilder {
    fn ether_type(&self) -> EtherType {
        EtherTypes::Arp
    }
}

impl Protocol for ArpBuilder {
    fn len(&self) -> usize {
        ArpPacket::minimum_packet_size()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        let mut arp_pkg = MutableArpPacket::new(buffer).unwrap();
        arp_pkg.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_pkg.set_protocol_type(EtherTypes::Ipv4);
        arp_pkg.set_hw_addr_len(6);
        arp_pkg.set_proto_addr_len(4);
        arp_pkg.set_operation(ArpOperations::Request);
        arp_pkg.set_sender_hw_addr(self.sender_mac);
        arp_pkg.set_sender_proto_addr(self.sender_ip);
        arp_pkg.set_target_hw_addr(MacAddr::new(0, 0, 0, 0, 0, 0));
        arp_pkg.set_target_proto_addr(self.target_ip);
    }
}
