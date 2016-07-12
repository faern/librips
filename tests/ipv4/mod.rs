use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::collections::HashMap;

use pnet::util::MacAddr;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes, MutableEthernetPacket};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{Packet, MutablePacket};

use rips::ipv4::{Ipv4Config, Ipv4Listener};

pub struct MockIpv4Listener {
    pub tx: mpsc::Sender<Vec<u8>>,
}

impl Ipv4Listener for MockIpv4Listener {
    fn recv(&mut self, packet: Ipv4Packet) {
        println!("MockIpv4Listener got a packet!");
        self.tx.send(packet.packet().to_vec()).unwrap();
    }
}

#[test]
fn test_simple_send() {
    let source_ip = Ipv4Addr::new(10, 1, 2, 3);
    let target_ip = Ipv4Addr::new(10, 1, 2, 2);
    let target_mac = MacAddr::new(9, 0, 0, 4, 0, 0);

    let (ethernet, ipv4_factory, _, read_handle) = ::dummy_ipv4(HashMap::new());

    // Inject an Arp entry so Ipv4 knows where to send
    let mut arp = ipv4_factory.arp_factory().arp(ethernet.clone());
    arp.insert(target_ip, target_mac);

    let conf = Ipv4Config::new(source_ip, 24, Ipv4Addr::new(10, 1, 2, 1)).unwrap();
    let mut ipv4 = ipv4_factory.ip(ethernet, conf);

    ipv4.send(target_ip, 2, |pkg| {
        pkg.set_payload(&[101, 204]);
    });

    let pkg = read_handle.recv().unwrap();
    let eth_pkg = EthernetPacket::new(&pkg[..]).unwrap();
    assert_eq!(eth_pkg.get_destination(), target_mac);
    assert_eq!(eth_pkg.get_ethertype(), EtherTypes::Ipv4);
    let ip_pkg = Ipv4Packet::new(eth_pkg.payload()).unwrap();
    assert_eq!(ip_pkg.get_version(), 4);
    assert_eq!(ip_pkg.get_source(), source_ip);
    assert_eq!(ip_pkg.get_destination(), target_ip);
    assert_eq!(ip_pkg.payload(), [101, 204]);
}

#[test]
fn test_simple_recv() {
    let source_ip = Ipv4Addr::new(10, 1, 2, 3);
    let target_ip = Ipv4Addr::new(10, 1, 2, 2);

    let mut ipv4_listeners = HashMap::new();
    let (tx, rx) = mpsc::channel();
    let ipv4_listener = MockIpv4Listener { tx: tx };
    ipv4_listeners.insert(IpNextHeaderProtocols::Igmp, Box::new(ipv4_listener) as Box<Ipv4Listener>);

    let (_ethernet, _, inject_handle, _) = ::dummy_ipv4(ipv4_listeners);

    let size = EthernetPacket::minimum_packet_size() + Ipv4Packet::minimum_packet_size() + 2;
    let mut buffer = vec![0; size];
    {
        let mut eth_pkg = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        eth_pkg.set_ethertype(EtherTypes::Ipv4);
        let mut ip_pkg = MutableIpv4Packet::new(eth_pkg.payload_mut()).unwrap();
        ip_pkg.set_header_length(5); // 5 is for no option fields
        ip_pkg.set_source(source_ip);
        ip_pkg.set_destination(target_ip);
        ip_pkg.set_next_level_protocol(IpNextHeaderProtocols::Igmp);
        ip_pkg.set_payload(&[67, 99]);
    }

    inject_handle.send(Ok(buffer.into_boxed_slice())).unwrap();

    let pkg = rx.recv().unwrap();
    let ip_pkg = Ipv4Packet::new(&pkg[..]).unwrap();
    assert_eq!(ip_pkg.get_source(), source_ip);
    assert_eq!(ip_pkg.get_destination(), target_ip);
    assert_eq!(ip_pkg.get_next_level_protocol(),
               IpNextHeaderProtocols::Igmp);
    assert_eq!(ip_pkg.payload(), [67, 99]);
}
