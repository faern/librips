mod ipv4_rx;
mod ipv4_tx;

pub use self::ipv4_rx::{BasicIpv4Listener, IpListenerLookup, Ipv4Listener, Ipv4Rx};
pub use self::ipv4_tx::{BasicIpv4Payload, Ipv4Builder, Ipv4Payload, Ipv4Tx, Ipv4TxImpl};

pub const MORE_FRAGMENTS: u8 = 0b001;
pub const DONT_FRAGMENT: u8 = 0b010;
pub const NO_FLAGS: u8 = 0b000;

#[cfg(test)]
mod tests {
    use RxError;
    use ethernet::EthernetListener;

    use pnet::packet::MutablePacket;
    use pnet::packet::ethernet::MutableEthernetPacket;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum};

    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};
    use std::sync::mpsc::{self, Receiver};
    use std::time::SystemTime;

    use super::*;

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

        let time = SystemTime::now();
        ipv4_rx.recv(time, &pkg.to_immutable()).unwrap();
        let (output_time, rx_ip_pkg) = rx.try_recv()
            .expect("Expected a packet to have been delivered");
        assert_eq!(time, output_time);
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
        let time = SystemTime::now();
        ipv4_rx.recv(time, &pkg.to_immutable()).unwrap();
        let (output_time, rx_ip_pkg) = rx.try_recv().unwrap();
        assert_eq!(time, output_time);
        assert_eq!(rx_ip_pkg.get_destination(), dst);
        assert_eq!(rx_ip_pkg.get_flags(), NO_FLAGS);
        assert_eq!(rx_ip_pkg.get_total_length(), 20 + 16 + 8);
        assert!(rx.try_recv().is_err());
    }

    fn setup_rx(dst: Ipv4Addr)
                -> (Box<EthernetListener>, Receiver<(SystemTime, Ipv4Packet<'static>)>) {
        let (tx, rx) = mpsc::channel();
        let arp_listener = BasicIpv4Listener::new(tx);

        let mut ip_listeners = HashMap::new();
        ip_listeners.insert(IpNextHeaderProtocols::Icmp, arp_listener);

        let mut listeners = HashMap::new();
        listeners.insert(dst, ip_listeners);

        let listeners = Arc::new(Mutex::new(listeners));
        let ipv4_rx = Ipv4Rx::new(listeners);
        (ipv4_rx, rx)
    }
}
