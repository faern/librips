use std::cmp;

use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::icmp::{IcmpCode, IcmpPacket, IcmpType, MutableIcmpPacket, checksum, IcmpTypes};
use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket, IcmpCodes};
use pnet::packet::MutablePacket;

use {Protocol, TxResult};
use ipv4::Ipv4Protocol;

#[cfg(all(test, feature = "unit-tests"))]
use testing::ipv4::Ipv4Tx;
#[cfg(not(all(test, feature = "unit-tests")))]
use ipv4::Ipv4Tx;

/// Trait for anything wishing to be the payload of an Icmp packet.
pub trait IcmpProtocol: Protocol {
    fn icmp_type(&self) -> IcmpType;

    fn icmp_code(&self) -> IcmpCode;
}

pub struct BasicIcmpProtocol {
    icmp_type: IcmpType,
    icmp_code: IcmpCode,
    offset: usize,
    payload: Vec<u8>,
}

impl BasicIcmpProtocol {
    pub fn new(icmp_type: IcmpType, icmp_code: IcmpCode, payload: Vec<u8>) -> Self {
        BasicIcmpProtocol {
            icmp_type: icmp_type,
            icmp_code: icmp_code,
            offset: 0,
            payload: payload,
        }
    }
}

impl IcmpProtocol for BasicIcmpProtocol {
    fn icmp_type(&self) -> IcmpType {
        self.icmp_type
    }

    fn icmp_code(&self) -> IcmpCode {
        self.icmp_code
    }
}

impl Protocol for BasicIcmpProtocol {
    fn len(&self) -> usize {
        self.payload.len()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        let mut pkg = MutableIcmpPacket::new(buffer).unwrap();
        let payload_buffer = pkg.payload_mut();
        let start = self.offset;
        let end = cmp::min(start + payload_buffer.len(), self.payload.len());
        self.offset = end;
        payload_buffer.copy_from_slice(&self.payload[start..end]);
    }
}

/// Icmp packet builder and sender struct.
pub struct IcmpTx {
    ipv4: Ipv4Tx,
}

impl IcmpTx {
    /// Creates a new `IcmpTx` based on `ipv4`
    pub fn new(ipv4: Ipv4Tx) -> IcmpTx {
        IcmpTx { ipv4: ipv4 }
    }

    /// Sends a general Icmp packet. Should not be called directly in general,
    /// instead use the specialized `send_echo` for ping packets.
    pub fn send<P>(&mut self, builder: P) -> TxResult
        where P: IcmpProtocol
    {
        let builder = IcmpBuilder::new(builder);
        self.ipv4.send(builder)
    }

    /// Sends an Echo Request packet (ping) with the given payload.
    pub fn send_echo(&mut self, payload: &[u8]) -> TxResult {
        let builder = PingBuilder::new(payload);
        self.send(builder)
    }
}


pub struct IcmpBuilder<P: IcmpProtocol> {
    builder: P,
}

impl<P: IcmpProtocol> IcmpBuilder<P> {
    pub fn new(builder: P) -> IcmpBuilder<P> {
        IcmpBuilder { builder: builder }
    }
}

impl<P: IcmpProtocol> Ipv4Protocol for IcmpBuilder<P> {
    fn next_level_protocol(&self) -> IpNextHeaderProtocol {
        IpNextHeaderProtocols::Icmp
    }
}

impl<P: IcmpProtocol> Protocol for IcmpBuilder<P> {
    fn len(&self) -> usize {
        IcmpPacket::minimum_packet_size() + self.builder.len()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        let mut pkg = MutableIcmpPacket::new(buffer).unwrap();
        pkg.set_icmp_type(self.builder.icmp_type());
        pkg.set_icmp_code(self.builder.icmp_code());
        self.builder.build(pkg.packet_mut());
        let checksum = checksum(&pkg.to_immutable());
        pkg.set_checksum(checksum);
    }
}

pub struct PingBuilder<'a> {
    payload: &'a [u8],
}

impl<'a> PingBuilder<'a> {
    pub fn new(payload: &'a [u8]) -> PingBuilder<'a> {
        PingBuilder { payload: payload }
    }
}

impl<'a> IcmpProtocol for PingBuilder<'a> {
    fn icmp_type(&self) -> IcmpType {
        IcmpTypes::EchoRequest
    }

    fn icmp_code(&self) -> IcmpCode {
        IcmpCodes::NoCode
    }
}

impl<'a> Protocol for PingBuilder<'a> {
    fn len(&self) -> usize {
        EchoRequestPacket::minimum_packet_size() - IcmpPacket::minimum_packet_size() +
        self.payload.len()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        let mut echo_pkg = MutableEchoRequestPacket::new(buffer).unwrap();
        echo_pkg.set_identifier(0);
        echo_pkg.set_sequence_number(0);
        echo_pkg.set_payload(self.payload);
    }
}
