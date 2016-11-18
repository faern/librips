use {Protocol, Tx, TxResult};

use pnet::packet::MutablePacket;
use pnet::packet::ethernet::{EtherType, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;

use std::cmp;

/// Trait for anything wishing to be the payload of an Ethernet frame.
pub trait EthernetProtocol: Protocol {
    fn ether_type(&self) -> EtherType;
}


/// Basic reference implementation of an `EthernetProtocol`.
/// Can be used to construct Ethernet frames with arbitrary payload from a
/// vector.
pub struct BasicEthernetProtocol {
    ether_type: EtherType,
    offset: usize,
    payload: Vec<u8>,
}

impl BasicEthernetProtocol {
    pub fn new(ether_type: EtherType, payload: Vec<u8>) -> Self {
        BasicEthernetProtocol {
            ether_type: ether_type,
            offset: 0,
            payload: payload,
        }
    }
}

impl EthernetProtocol for BasicEthernetProtocol {
    fn ether_type(&self) -> EtherType {
        self.ether_type
    }
}

impl Protocol for BasicEthernetProtocol {
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

pub trait EthernetTx {
    fn src(&self) -> MacAddr;
    fn dst(&self) -> MacAddr;
    fn send<P>(&mut self, packets: usize, size: usize, payload: P) -> TxResult
        where P: EthernetProtocol;
}

pub struct EthernetTxImpl<T: Tx> {
    src: MacAddr,
    dst: MacAddr,
    tx: T,
}

impl<T: Tx> EthernetTxImpl<T> {
    pub fn new(tx: T, src: MacAddr, dst: MacAddr) -> Self {
        EthernetTxImpl {
            src: src,
            dst: dst,
            tx: tx,
        }
    }
}

impl<T: Tx> EthernetTx for EthernetTxImpl<T> {
    fn src(&self) -> MacAddr {
        self.src
    }

    fn dst(&self) -> MacAddr {
        self.dst
    }

    /// Send ethernet packets to the network.
    ///
    /// For every packet, all `header_size+size` bytes will be sent, no
    /// matter how small payload is provided to the `MutableEthernetPacket` in
    /// the call to `builder`. So in total `packets * (header_size+size)` bytes
    /// will be sent. This is  usually not a problem since the IP layer has the
    /// length in the header and the extra bytes should thus not cause any
    /// trouble.
    fn send<P>(&mut self, packets: usize, size: usize, payload: P) -> TxResult
        where P: EthernetProtocol
    {
        let mut builder = EthernetBuilder::new(self.src, self.dst, payload);
        let total_size = size + EthernetPacket::minimum_packet_size();
        self.tx.send(packets, total_size, |pkg| builder.build(pkg))
    }
}

/// Struct building Ethernet frames
pub struct EthernetBuilder<P: EthernetProtocol> {
    src: MacAddr,
    dst: MacAddr,
    payload: P,
}

impl<P: EthernetProtocol> EthernetBuilder<P> {
    /// Creates a new `EthernetBuilder` with the given parameters
    pub fn new(src: MacAddr, dst: MacAddr, payload: P) -> Self {
        EthernetBuilder {
            src: src,
            dst: dst,
            payload: payload,
        }
    }

    pub fn len(&self) -> usize {
        EthernetPacket::minimum_packet_size() + self.payload.len()
    }

    /// Modifies `pkg` to have the correct header and payload
    pub fn build(&mut self, mut pkg: MutableEthernetPacket) {
        pkg.set_source(self.src);
        pkg.set_destination(self.dst);
        pkg.set_ethertype(self.payload.ether_type());
        self.payload.build(pkg.payload_mut());
    }
}
