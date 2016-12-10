use {Payload, TxResult};
use ethernet::EthernetPayload;
use ethernet::EthernetTx;

use pnet::packet::{MutablePacket, Packet};
use pnet::packet::ethernet::{EtherType, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum};

use std::cmp;
use std::net::Ipv4Addr;

use super::{MORE_FRAGMENTS, NO_FLAGS};

pub trait Ipv4Payload: Payload {
    fn next_level_protocol(&self) -> IpNextHeaderProtocol;
}


pub struct BasicIpv4Payload {
    next_level_protocol: IpNextHeaderProtocol,
    offset: usize,
    payload: Vec<u8>,
}

impl BasicIpv4Payload {
    pub fn new(next_level_protocol: IpNextHeaderProtocol, payload: Vec<u8>) -> Self {
        assert!(payload.len() <= ::std::u16::MAX as usize);
        BasicIpv4Payload {
            next_level_protocol: next_level_protocol,
            offset: 0,
            payload: payload,
        }
    }
}

impl Ipv4Payload for BasicIpv4Payload {
    fn next_level_protocol(&self) -> IpNextHeaderProtocol {
        self.next_level_protocol
    }
}

impl Payload for BasicIpv4Payload {
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


pub trait Ipv4Tx {
    fn src(&self) -> Ipv4Addr;
    fn dst(&self) -> Ipv4Addr;
    fn send<P: Ipv4Payload>(&mut self, payload: P) -> TxResult;
}

/// IPv4 packet builder and sender. Will fragment packets larger than the
/// MTU reported by the underlying `EthernetTx` given to the constructor.
pub struct Ipv4TxImpl<T: EthernetTx> {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    mtu: usize,
    ethernet: T,
    next_identification: u16,
}

impl<T: EthernetTx> Ipv4TxImpl<T> {
    /// Constructs a new `Ipv4Tx`.
    ///
    /// # Panics
    ///
    /// Panics if `mtu` is smaller than the minimum Ipv4 packet size.
    pub fn new(ethernet: T, src: Ipv4Addr, dst: Ipv4Addr, mtu: usize) -> Self {
        assert!(mtu >= Ipv4Packet::minimum_packet_size());
        Ipv4TxImpl {
            src: src,
            dst: dst,
            mtu: mtu,
            ethernet: ethernet,
            next_identification: 0,
        }
    }

    pub fn max_payload_per_fragment(&self) -> usize {
        (self.mtu - Ipv4Packet::minimum_packet_size()) & !0b111
    }
}

impl<T: EthernetTx> Ipv4Tx for Ipv4TxImpl<T> {
    fn src(&self) -> Ipv4Addr {
        self.src
    }

    fn dst(&self) -> Ipv4Addr {
        self.dst
    }

    fn send<P: Ipv4Payload>(&mut self, payload: P) -> TxResult {
        let payload_len = payload.len() as usize;
        let builder = Ipv4Builder::new(self.src, self.dst, self.next_identification, payload);
        self.next_identification.wrapping_add(1);

        let max_payload_per_fragment = self.max_payload_per_fragment();
        if payload_len <= max_payload_per_fragment {
            let size = payload_len + Ipv4Packet::minimum_packet_size();
            self.ethernet.send(1, size, builder)
        } else {
            let fragments = 1 + ((payload_len - 1) / max_payload_per_fragment);
            let size = max_payload_per_fragment + Ipv4Packet::minimum_packet_size();
            self.ethernet.send(fragments, size, builder)
        }
    }
}


pub struct Ipv4Builder<P: Ipv4Payload> {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    offset: usize,
    identification: u16,
    payload: P,
}

impl<P: Ipv4Payload> Ipv4Builder<P> {
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

impl<P: Ipv4Payload> EthernetPayload for Ipv4Builder<P> {
    fn ether_type(&self) -> EtherType {
        EtherTypes::Ipv4
    }
}

impl<P: Ipv4Payload> Payload for Ipv4Builder<P> {
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


#[cfg(test)]
mod ipv4_tx_tests {
    use TxResult;
    use ethernet::{EthernetPayload, EthernetTx};

    use pnet::packet::Packet;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::util::MacAddr;

    use std::net::Ipv4Addr;
    use std::sync::mpsc;

    use super::*;
    use super::super::MORE_FRAGMENTS;

    lazy_static! {
        static ref SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
        static ref DST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    }


    #[derive(Debug)]
    pub struct MockEthernetTx {
        chan: mpsc::Sender<Box<[u8]>>,
    }

    impl MockEthernetTx {
        pub fn new() -> (MockEthernetTx, mpsc::Receiver<Box<[u8]>>) {
            let (tx, rx) = mpsc::channel();
            (MockEthernetTx { chan: tx }, rx)
        }
    }

    impl EthernetTx for MockEthernetTx {
        fn src(&self) -> MacAddr {
            MacAddr::new(0, 0, 0, 0, 0, 0)
        }

        fn dst(&self) -> MacAddr {
            MacAddr::new(0, 0, 0, 0, 0, 0)
        }

        fn send<P>(&mut self, packets: usize, packet_size: usize, mut payload: P) -> TxResult
            where P: EthernetPayload
        {
            for _ in 0..packets {
                let mut buffer = vec![0; packet_size];
                payload.build(&mut buffer[..]);
                self.chan.send(buffer.into_boxed_slice()).unwrap();
            }
            Ok(())
        }
    }

    #[test]
    fn mtu() {
        let (eth_tx, _) = MockEthernetTx::new();
        let testee = Ipv4TxImpl::new(eth_tx, *SRC_IP, *DST_IP, 28);
        assert_eq!(8, testee.max_payload_per_fragment());
    }

    #[test]
    fn mtu_zero() {
        let (eth_tx, _) = MockEthernetTx::new();
        let testee = Ipv4TxImpl::new(eth_tx, *SRC_IP, *DST_IP, 27);
        assert_eq!(0, testee.max_payload_per_fragment());
    }

    #[test]
    #[should_panic]
    fn mtu_smaller_than_header() {
        let (eth_tx, _) = MockEthernetTx::new();
        let _testee = Ipv4TxImpl::new(eth_tx, *SRC_IP, *DST_IP, 19);
    }

    #[test]
    fn tx_fragmented() {
        let (eth_tx, rx) = MockEthernetTx::new();
        let mut testee = Ipv4TxImpl::new(eth_tx, *SRC_IP, *DST_IP, 20 + 8);

        let payload = BasicIpv4Payload::new(IpNextHeaderProtocols::Tcp, (0..10).collect());
        testee.send(payload).unwrap();

        let pkg1 = rx.try_recv().unwrap();
        let pkg2 = rx.try_recv().unwrap();
        assert!(rx.try_recv().is_err());

        let id1 = check_pkg(&pkg1, *SRC_IP, *DST_IP, true, 0, &[0, 1, 2, 3, 4, 5, 6, 7]);
        let id2 = check_pkg(&pkg2, *SRC_IP, *DST_IP, false, 8, &[8, 9]);
        assert_eq!(id1, id2);
    }

    #[test]
    fn tx_not_fragmented() {
        let (eth_tx, rx) = MockEthernetTx::new();
        let mut ipv4_tx = Ipv4TxImpl::new(eth_tx, *SRC_IP, *DST_IP, 1500);

        let payload_data = (0..100).collect::<Vec<u8>>();
        let payload = BasicIpv4Payload::new(IpNextHeaderProtocols::Tcp, payload_data.clone());
        ipv4_tx.send(payload).unwrap();

        let pkg = rx.try_recv().unwrap();
        assert!(rx.try_recv().is_err());

        check_pkg(&pkg, *SRC_IP, *DST_IP, false, 0, &payload_data);
    }

    fn check_pkg(pkg_buffer: &[u8],
                 src: Ipv4Addr,
                 dst: Ipv4Addr,
                 is_fragment: bool,
                 offset: u16,
                 payload: &[u8])
                 -> u16 {
        let pkg = Ipv4Packet::new(pkg_buffer).unwrap();
        assert_eq!(src, pkg.get_source());
        assert_eq!(dst, pkg.get_destination());;
        assert_eq!(is_fragment, pkg.get_flags() == MORE_FRAGMENTS);
        assert_eq!(offset, pkg.get_fragment_offset() * 8);
        assert_eq!(payload.len() + Ipv4Packet::minimum_packet_size(),
                   pkg.get_total_length() as usize);
        assert_eq!(payload, &pkg.payload()[0..payload.len()]);
        pkg.get_identification()
    }
}
