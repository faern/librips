use {Payload, HasPayload, BasicPayload, Tx, TxResult};

use pnet::packet::MutablePacket;
use pnet::packet::ethernet::{EtherType, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;

/// Trait for anything wishing to be the payload of an Ethernet frame.
pub trait EthernetPayload: Payload {
    fn ether_type(&self) -> EtherType;
}


/// Basic reference implementation of an `EthernetPayload`.
/// Can be used to construct Ethernet frames with arbitrary payload from a
/// vector.
pub struct BasicEthernetPayload<'a> {
    ether_type: EtherType,
    payload: BasicPayload<'a>,
}

impl<'a> BasicEthernetPayload<'a> {
    pub fn new(ether_type: EtherType, payload: &'a [u8]) -> Self {
        BasicEthernetPayload {
            ether_type: ether_type,
            payload: BasicPayload::new(payload),
        }
    }
}

impl<'a> EthernetPayload for BasicEthernetPayload<'a> {
    fn ether_type(&self) -> EtherType {
        self.ether_type
    }
}

impl<'a> HasPayload for BasicEthernetPayload<'a> {
    fn get_payload(&self) -> &Payload {
        &self.payload
    }

    fn get_payload_mut(&mut self) -> &mut Payload {
        &mut self.payload
    }
}

#[cfg(test)]
mod basic_ethernet_payload_tests {
    use Payload;
    use pnet::packet::ethernet::EtherTypes;
    use super::*;

    #[test]
    fn ether_type() {
        let testee = BasicEthernetPayload::new(EtherTypes::Ipv6, &[]);
        assert_eq!(EtherTypes::Ipv6, testee.ether_type());
    }

    #[test]
    fn len_zero() {
        let testee = BasicEthernetPayload::new(EtherTypes::Arp, &[]);
        assert_eq!(0, testee.len());
    }

    #[test]
    fn len_three() {
        let data = &[5, 6, 7];
        let testee = BasicEthernetPayload::new(EtherTypes::Arp, data);
        assert_eq!(3, testee.len());
    }

    #[test]
    fn build_without_data() {
        let mut testee = BasicEthernetPayload::new(EtherTypes::Arp, &[]);
        let mut buffer = vec![99; 1];
        testee.build(&mut buffer);
        assert_eq!(99, buffer[0]);
    }

    #[test]
    fn build_with_data() {
        let data = &[5, 6, 7];
        let mut testee = BasicEthernetPayload::new(EtherTypes::Arp, data);
        let mut buffer = vec![0; 1];
        testee.build(&mut buffer[0..0]);

        testee.build(&mut buffer);
        assert_eq!(5, buffer[0]);
        testee.build(&mut buffer);
        assert_eq!(6, buffer[0]);
        testee.build(&mut buffer);
        assert_eq!(7, buffer[0]);

        testee.build(&mut buffer[0..0]);
    }

    #[test]
    fn build_with_larger_buffer() {
        let data = &[5, 6];
        let mut testee = BasicEthernetPayload::new(EtherTypes::Arp, data);
        let mut buffer = vec![0; 3];
        testee.build(&mut buffer);
        assert_eq!(&[5, 6, 0], &buffer[..]);
    }
}


pub trait EthernetTx {
    fn src(&self) -> MacAddr;
    fn dst(&self) -> MacAddr;
    fn send<P>(&mut self, packets: usize, size: usize, payload: P) -> TxResult
        where P: EthernetPayload;
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
        where P: EthernetPayload
    {
        let builder = EthernetBuilder::new(self.src, self.dst, payload);
        let size_with_header = size + EthernetPacket::minimum_packet_size();
        self.tx.send(packets, size_with_header, builder)
    }
}


/// Struct building Ethernet frames
pub struct EthernetBuilder<P: EthernetPayload> {
    src: MacAddr,
    dst: MacAddr,
    payload: P,
}

impl<P: EthernetPayload> EthernetBuilder<P> {
    /// Creates a new `EthernetBuilder` with the given parameters
    pub fn new(src: MacAddr, dst: MacAddr, payload: P) -> Self {
        EthernetBuilder {
            src: src,
            dst: dst,
            payload: payload,
        }
    }
}

impl<P: EthernetPayload> Payload for EthernetBuilder<P> {
    fn len(&self) -> usize {
        EthernetPacket::minimum_packet_size() + self.payload.len()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        let mut pkg = MutableEthernetPacket::new(buffer).unwrap();
        pkg.set_source(self.src);
        pkg.set_destination(self.dst);
        pkg.set_ethertype(self.payload.ether_type());
        self.payload.build(pkg.payload_mut());
    }
}


#[cfg(test)]
mod ethernet_tx_tests {
    use {TxResult, TxError, Tx, Payload};

    use pnet::packet::Packet;
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
    use pnet::util::MacAddr;

    use std::error::Error;
    use std::sync::mpsc::{self, Sender, Receiver};

    use super::*;

    pub struct MockTx {
        chan: Sender<Box<[u8]>>,
    }

    impl MockTx {
        pub fn new() -> (Self, Receiver<Box<[u8]>>) {
            let (tx, rx) = mpsc::channel();
            (MockTx { chan: tx }, rx)
        }
    }

    impl Tx for MockTx {
        fn send<P>(&mut self, packets: usize, size: usize, mut payload: P) -> TxResult
            where P: Payload
        {
            for _ in 0..packets {
                let mut buffer = vec![0; size];
                payload.build(&mut buffer[..]);
                self.chan
                    .send(buffer.into_boxed_slice())
                    .map_err(|e| TxError::Other(e.description().to_owned()))?;
            }
            Ok(())
        }
    }

    lazy_static! {
        static ref SRC: MacAddr = MacAddr::new(0, 0, 0, 0, 0, 1);
        static ref DST: MacAddr = MacAddr::new(0, 0, 0, 0, 0, 2);
    }

    #[test]
    fn new() {
        let (mock_tx, _) = MockTx::new();
        let testee = EthernetTxImpl::new(mock_tx, *SRC, *DST);
        assert_eq!(*SRC, testee.src());
        assert_eq!(*DST, testee.dst());
    }

    #[test]
    fn send() {
        let (mock_tx, rx) = MockTx::new();
        let mut testee = EthernetTxImpl::new(mock_tx, *SRC, *DST);

        let data = &[8, 7, 6];
        let payload = BasicEthernetPayload::new(EtherTypes::Arp, data);

        testee.send(1, 3, payload).unwrap();

        let buffer = rx.try_recv().unwrap();
        assert!(rx.try_recv().is_err());

        let pkg = EthernetPacket::new(&buffer).unwrap();
        assert_eq!(*SRC, pkg.get_source());
        assert_eq!(*DST, pkg.get_destination());
        assert_eq!(EtherTypes::Arp, pkg.get_ethertype());
        assert_eq!(data, pkg.payload());
    }
}
