use std::net::Ipv4Addr;
use std::cmp;

use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum};
use pnet::packet::ethernet::{EtherType, EtherTypes};
use pnet::packet::{MutablePacket, Packet};

use {Protocol, TxResult};
use ethernet::EthernetProtocol;
use super::{NO_FLAGS, MORE_FRAGMENTS};

#[cfg(all(test, feature = "unit-tests"))]
use testing::ethernet::EthernetTx;
#[cfg(not(all(test, feature = "unit-tests")))]
use ethernet::EthernetTx;

pub trait Ipv4Protocol: Protocol {
    fn next_level_protocol(&self) -> IpNextHeaderProtocol;
}

pub struct BasicIpv4Protocol {
    next_level_protocol: IpNextHeaderProtocol,
    offset: usize,
    payload: Vec<u8>,
}

impl BasicIpv4Protocol {
    pub fn new(next_level_protocol: IpNextHeaderProtocol, payload: Vec<u8>) -> Self {
        assert!(payload.len() <= ::std::u16::MAX as usize);
        BasicIpv4Protocol {
            next_level_protocol: next_level_protocol,
            offset: 0,
            payload: payload,
        }
    }
}

impl Ipv4Protocol for BasicIpv4Protocol {
    fn next_level_protocol(&self) -> IpNextHeaderProtocol {
        self.next_level_protocol
    }
}

impl Protocol for BasicIpv4Protocol {
    fn len(&self) -> usize {
        self.payload.len()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        let start = self.offset;
        let end = cmp::min(start + buffer.len(), self.payload.len());
        self.offset = end;
        buffer.copy_from_slice(&self.payload[start..end]);
    }
}


/// IPv4 packet builder and sender. Will fragment packets larger than the
/// MTU reported by the underlying `EthernetTx` given to the constructor.
pub struct Ipv4Tx {
    /// The source IP of packets built by this instance.
    pub src: Ipv4Addr,

    /// The destination IP of the packets built by this instance.
    pub dst: Ipv4Addr,

    mtu: usize,

    ethernet: EthernetTx,
    next_identification: u16,
}

impl Ipv4Tx {
    /// Constructs a new `Ipv4Tx`.
    pub fn new(ethernet: EthernetTx, src: Ipv4Addr, dst: Ipv4Addr, mtu: usize) -> Ipv4Tx {
        assert!(mtu >= Ipv4Packet::minimum_packet_size());
        Ipv4Tx {
            src: src,
            dst: dst,
            mtu: mtu,
            ethernet: ethernet,
            next_identification: 0,
        }
    }

    /// Sends an IPv4 packet to the network. If the given `dst_ip` is within
    /// the local network it will be sent directly to the MAC of that IP (taken
    /// from arp), otherwise it will be sent to the MAC of the configured
    /// gateway.
    pub fn send<P: Ipv4Protocol>(&mut self, payload: P) -> TxResult {
        let payload_len = payload.len();
        let builder = Ipv4Builder::new(self.src, self.dst, self.next_identification, payload);
        self.next_identification.wrapping_add(1);

        let max_payload_per_fragment = self.max_payload_per_fragment();
        if payload_len as usize <= max_payload_per_fragment {
            let size = payload_len as usize + Ipv4Packet::minimum_packet_size();
            self.ethernet.send(1, size, builder)
        } else {
            let fragments = 1 + ((payload_len as usize - 1) / max_payload_per_fragment);
            let size = max_payload_per_fragment + Ipv4Packet::minimum_packet_size();
            self.ethernet.send(fragments, size, builder)
        }
    }

    pub fn max_payload_per_fragment(&self) -> usize {
        (self.mtu - Ipv4Packet::minimum_packet_size()) & !0b111
    }
}


pub struct Ipv4Builder<P: Ipv4Protocol> {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    offset: usize,
    identification: u16,
    payload: P,
}

impl<P: Ipv4Protocol> Ipv4Builder<P> {
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, identification: u16, payload: P) -> Self {
        Ipv4Builder {
            src: src,
            dst: dst,
            offset: 0,
            identification: identification,
            payload: payload,
        }
    }
}

impl<P: Ipv4Protocol> EthernetProtocol for Ipv4Builder<P> {
    fn ether_type(&self) -> EtherType {
        EtherTypes::Ipv4
    }
}

impl<P: Ipv4Protocol> Protocol for Ipv4Builder<P> {
    fn len(&self) -> usize {
        Ipv4Packet::minimum_packet_size() + self.payload.len()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        assert!(buffer.len() <= ::std::u16::MAX as usize);
        let mut pkg = MutableIpv4Packet::new(buffer).unwrap();
        pkg.set_version(4);
        pkg.set_dscp(0); // https://en.wikipedia.org/wiki/Differentiated_services
        pkg.set_ecn(0); // https://en.wikipedia.org/wiki/Explicit_Congestion_Notification
        pkg.set_ttl(40);
        // ip_pkg.set_options(vec![]); // We currently don't support options
        pkg.set_header_length(5); // 5 is for no option fields
        pkg.set_identification(self.identification);
        pkg.set_source(self.src);
        pkg.set_destination(self.dst);
        pkg.set_fragment_offset((self.offset / 8) as u16);

        let bytes_remaining = self.payload.len() - self.offset;
        let bytes_max = pkg.payload().len();
        let payload_size = if bytes_remaining <= bytes_max {
            pkg.set_flags(NO_FLAGS);
            bytes_remaining
        } else {
            pkg.set_flags(MORE_FRAGMENTS);
            bytes_max & !0b111 // Round down to divisable by 8
        };
        let total_length = payload_size + Ipv4Packet::minimum_packet_size();
        pkg.set_total_length(total_length as u16);

        pkg.set_next_level_protocol(self.payload.next_level_protocol());
        self.payload.build(&mut pkg.payload_mut()[..payload_size]);

        let checksum = checksum(&pkg.to_immutable());
        pkg.set_checksum(checksum);

        self.offset += payload_size;
    }
}
