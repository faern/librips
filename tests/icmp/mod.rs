use std::net::Ipv4Addr;
use std::sync::mpsc;

use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::icmp::echo_request::EchoRequestPacket;
use pnet::packet::icmp::{IcmpPacket, MutableIcmpPacket, icmp_types};
use pnet::packet::{Packet, MutablePacket};

use rips::icmp::{Icmp, Echo, IcmpListener};

pub struct MockIcmpListener {
    pub tx: mpsc::Sender<Vec<u8>>,
}

impl IcmpListener for MockIcmpListener {
    fn recv(&mut self, packet: Ipv4Packet) {
        println!("MockIcmpListener got a packet!");
        self.tx.send(packet.packet().to_vec()).unwrap();
    }
}

#[test]
fn test_ping() {
    let (_ethernet, _, ipv4, _, read_handle) = ::dummy_icmp();

    let icmp = Icmp::new(ipv4);
    let mut echo = Echo::new(icmp);

    echo.send(Ipv4Addr::new(10, 0, 0, 1), &[9, 55]).unwrap().unwrap();

    let pkg = read_handle.recv().unwrap();
    let eth_pkg = EthernetPacket::new(&pkg[..]).unwrap();
    let ip_pkg = Ipv4Packet::new(eth_pkg.payload()).unwrap();
    assert_eq!(ip_pkg.get_next_level_protocol(),
               IpNextHeaderProtocols::Icmp);
    let echo_pkg = EchoRequestPacket::new(ip_pkg.payload()).unwrap();
    assert_eq!(echo_pkg.get_icmp_type(), icmp_types::EchoRequest);
    assert_eq!(echo_pkg.get_icmp_code().0, 0);
    assert_eq!(echo_pkg.get_checksum(), 61128);
    assert_eq!(echo_pkg.payload(), [9, 55]);
}

#[test]
fn recv_icmp() {
    let source_ip = Ipv4Addr::new(10, 1, 2, 3);
    let target_ip = Ipv4Addr::new(10, 1, 2, 2);

    let (tx, rx) = mpsc::channel();
    let mock_icmp_listener = MockIcmpListener { tx: tx };

    let (_ethernet, icmp_factory, _, inject_handle, _) = ::dummy_icmp();
    icmp_factory.add_listener(icmp_types::DestinationUnreachable, mock_icmp_listener);

    let size = EthernetPacket::minimum_packet_size() + Ipv4Packet::minimum_packet_size() + IcmpPacket::minimum_packet_size();
    let mut buffer = vec![0; size];
    {
        let mut eth_pkg = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        eth_pkg.set_ethertype(EtherTypes::Ipv4);
        let mut ip_pkg = MutableIpv4Packet::new(eth_pkg.payload_mut()).unwrap();
        ip_pkg.set_header_length(5); // 5 is for no option fields
        ip_pkg.set_source(source_ip);
        ip_pkg.set_destination(target_ip);
        ip_pkg.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        let mut icmp_pkg = MutableIcmpPacket::new(ip_pkg.payload_mut()).unwrap();
        icmp_pkg.set_icmp_type(icmp_types::DestinationUnreachable);
    }

    inject_handle.send(Ok(buffer.into_boxed_slice())).unwrap();

    let pkg = rx.recv().unwrap();
    let ip_pkg = Ipv4Packet::new(&pkg[..]).unwrap();
    assert_eq!(ip_pkg.get_source(), source_ip);
    assert_eq!(ip_pkg.get_destination(), target_ip);
    assert_eq!(ip_pkg.get_next_level_protocol(),
               IpNextHeaderProtocols::Icmp);
    let icmp_pkg = IcmpPacket::new(ip_pkg.payload()).unwrap();
    assert_eq!(icmp_pkg.get_icmp_type(), icmp_types::DestinationUnreachable);
}
