mod ipv4_rx;
mod ipv4_tx;

pub use self::ipv4_rx::{IpListenerLookup, Ipv4Listener, Ipv4Rx};
pub use self::ipv4_tx::{BasicIpv4Payload, Ipv4Builder, Ipv4Payload, Ipv4Tx, Ipv4TxImpl};

pub const MORE_FRAGMENTS: u8 = 0b001;
pub const DONT_FRAGMENT: u8 = 0b010;
pub const NO_FLAGS: u8 = 0b000;

#[cfg(test)]
mod tests {
    use RxError;
    use ethernet::EthernetListener;
    use pnet::packet::{MutablePacket, Packet};
    use pnet::packet::ethernet::MutableEthernetPacket;

    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex, mpsc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::SystemTime;

    use super::*;
    use testing::{ethernet, ipv4};
    use testing::ipv4::TestIpv4Payload;

    #[test]
    fn tx_fragmented() {
        let src = Ipv4Addr::new(192, 168, 10, 2);
        let dst = Ipv4Addr::new(192, 168, 10, 240);

        let (eth_tx, rx) = ethernet::MockEthernetTx::new();
        let mut ipv4_tx = Ipv4TxImpl::new(eth_tx, src, dst, 1500);

        let max_payload_len = ipv4_tx.max_payload_per_fragment();
        let pkg_size = max_payload_len + 5;

        let call_count = AtomicUsize::new(0);
        let call_bytes = AtomicUsize::new(0);
        let builder = TestIpv4Payload::new_counted(pkg_size, &call_count, &call_bytes);
        assert!(ipv4_tx.send(builder).is_ok());
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
        assert_eq!(call_bytes.load(Ordering::SeqCst), pkg_size);

        let frame1 = rx.try_recv().expect("Expected a frame to have been sent");
        let frame2 = rx.try_recv().expect("Expected a second frame to have been sent");
        assert!(rx.try_recv().is_err());
        let id1 = check_pkg(&frame1, src, dst, max_payload_len, true, 0, 100, 99);
        let id2 = check_pkg(&frame2, src, dst, 5, false, max_payload_len as u16, 100, 99);
        assert_eq!(id1, id2);
    }

    #[test]
    fn tx_not_fragmented() {
        let src = Ipv4Addr::new(192, 168, 10, 2);
        let dst = Ipv4Addr::new(192, 168, 10, 240);

        let (eth_tx, rx) = ethernet::MockEthernetTx::new();
        let mut ipv4_tx = Ipv4TxImpl::new(eth_tx, src, dst, 1500);

        let max_payload_len = ipv4_tx.max_payload_per_fragment();
        let pkg_size = max_payload_len - 5;

        let call_count = AtomicUsize::new(0);
        let call_bytes = AtomicUsize::new(0);
        let builder = TestIpv4Payload::new_counted(pkg_size, &call_count, &call_bytes);
        assert!(ipv4_tx.send(builder).is_ok());
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
        assert_eq!(call_bytes.load(Ordering::SeqCst), pkg_size);

        let frame = rx.try_recv().expect("Expected a frame to have been sent");
        assert!(rx.try_recv().is_err());
        check_pkg(&frame, src, dst, pkg_size, false, 0, 100, 99);
    }

    #[test]
    fn rx_not_fragmented() {
        let dst = Ipv4Addr::new(127, 0, 0, 1);
        let (mut ipv4_rx, rx) = setup_rx(dst);

        let mut buffer = vec![0; 100];
        let mut pkg = MutableEthernetPacket::new(&mut buffer).unwrap();
        {
            let mut ip_pkg = MutableIpv4Packet::new(pkg.payload_mut()).unwrap();
            ip_pkg.set_destination(dst);
            ip_pkg.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ip_pkg.set_flags(DONT_FRAGMENT);
            ip_pkg.set_header_length(5); // No options
            ip_pkg.set_total_length(20 + 15);
            let csum = checksum(&ip_pkg.to_immutable());
            ip_pkg.set_checksum(csum);
        }

        ipv4_rx.recv(SystemTime::now(), &pkg.to_immutable()).unwrap();
        let rx_pkg = rx.try_recv().expect("Expected a packet to have been delivered");
        let rx_ip_pkg = Ipv4Packet::new(&rx_pkg[..]).unwrap();
        assert_eq!(rx_ip_pkg.get_destination(), dst);
        assert_eq!(rx_ip_pkg.get_flags(), DONT_FRAGMENT);
        assert_eq!(rx_ip_pkg.get_total_length(), 35);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn rx_fragmented() {
        let dst = Ipv4Addr::new(127, 0, 0, 1);
        let (mut ipv4_rx, rx) = setup_rx(dst);

        let mut buffer = vec![0; 100];
        let mut pkg = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        // Send first part of a fragmented packet and make sure nothing is sent to the
        // listener
        {
            let mut ip_pkg = MutableIpv4Packet::new(pkg.payload_mut()).unwrap();
            ip_pkg.set_destination(dst);
            ip_pkg.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ip_pkg.set_flags(MORE_FRAGMENTS);
            ip_pkg.set_fragment_offset(0);
            ip_pkg.set_identification(137);
            ip_pkg.set_header_length(5); // No options
            ip_pkg.set_total_length(20 + 16);
            let csum = checksum(&ip_pkg.to_immutable());
            ip_pkg.set_checksum(csum);
        }

        ipv4_rx.recv(SystemTime::now(), &pkg.to_immutable()).unwrap();
        assert!(rx.try_recv().is_err());

        // Send a packet with different identification number and make sure it doesn't
        // merge
        {
            let mut ip_pkg = MutableIpv4Packet::new(pkg.payload_mut()).unwrap();
            ip_pkg.set_flags(NO_FLAGS);
            ip_pkg.set_fragment_offset(16 / 8);
            ip_pkg.set_identification(299);
            ip_pkg.set_total_length(20 + 8);
            let csum = checksum(&ip_pkg.to_immutable());
            ip_pkg.set_checksum(csum);
        }
        assert_eq!(ipv4_rx.recv(SystemTime::now(), &pkg.to_immutable()),
                   Err(RxError::InvalidContent));
        assert!(rx.try_recv().is_err());

        // Send final part of fragmented packet
        {
            let mut ip_pkg = MutableIpv4Packet::new(pkg.payload_mut()).unwrap();
            ip_pkg.set_identification(137);
            let csum = checksum(&ip_pkg.to_immutable());
            ip_pkg.set_checksum(csum);
        }
        ipv4_rx.recv(SystemTime::now(), &pkg.to_immutable()).unwrap();
        let rx_pkg = rx.try_recv().expect("Expected a packet to have been delivered");
        let rx_ip_pkg = Ipv4Packet::new(&rx_pkg[..]).unwrap();
        assert_eq!(rx_ip_pkg.get_destination(), dst);
        assert_eq!(rx_ip_pkg.get_flags(), NO_FLAGS);
        assert_eq!(rx_ip_pkg.get_total_length(), 20 + 16 + 8);
        assert!(rx.try_recv().is_err());
    }

    fn setup_rx(dst: Ipv4Addr) -> (Box<EthernetListener>, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel();
        let arp_listener = Box::new(ipv4::MockIpv4Listener { tx: tx }) as Box<Ipv4Listener>;

        let mut ip_listeners = HashMap::new();
        ip_listeners.insert(IpNextHeaderProtocols::Icmp, arp_listener);

        let mut listeners = HashMap::new();
        listeners.insert(dst, ip_listeners);

        let listeners = Arc::new(Mutex::new(listeners));
        let ipv4_rx = Ipv4Rx::new(listeners);
        (ipv4_rx, rx)
    }

    fn check_pkg(payload: &[u8],
                 src: Ipv4Addr,
                 dst: Ipv4Addr,
                 payload_len: usize,
                 is_fragment: bool,
                 offset: u16,
                 first: u8,
                 last: u8)
                 -> u16 {
        let ip_pkg = Ipv4Packet::new(payload).unwrap();
        assert_eq!(ip_pkg.get_source(), src);
        assert_eq!(ip_pkg.get_destination(), dst);;
        assert_eq!(ip_pkg.get_total_length() as usize,
                   payload_len + Ipv4Packet::minimum_packet_size());
        assert_eq!(ip_pkg.get_flags() == MORE_FRAGMENTS, is_fragment);
        assert_eq!(ip_pkg.get_fragment_offset() * 8, offset);
        let payload = ip_pkg.payload();
        assert_eq!(payload[0], first);
        assert_eq!(payload[payload_len - 1], last);
        ip_pkg.get_identification()
    }
}
