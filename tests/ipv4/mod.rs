use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::collections::HashMap;

use pnet::util::MacAddr;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes, MutableEthernetPacket};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{Packet, MutablePacket};

use rips::ethernet::EthernetListener;
use rips::arp::{Arp, ArpFactory};
use rips::ipv4::{Ipv4Config, Ipv4, Ipv4Listener, Ipv4Factory};

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

    let mut listeners = HashMap::new();

    let arp_factory = ArpFactory::new();
    let arp_listener = arp_factory.listener();
    listeners.insert(EtherTypes::Arp, Box::new(arp_listener) as Box<EthernetListener>);

    let mut ipv4_factory = Ipv4Factory::new(arp_factory, HashMap::new());
    let ipv4_listener = ipv4_factory.listener().unwrap();
    listeners.insert(EtherTypes::Ipv4, Box::new(ipv4_listener) as Box<EthernetListener>);

    let (ethernet, source_mac, _, read_handle) = ::dummy_ethernet(7, listeners);

    // Inject an Arp entry so Ipv4 knows where to send
    let mut arp = Arp::new(ethernet.clone());
    arp.insert(target_ip, target_mac);

    let conf = Ipv4Config::new(source_ip, 24, Ipv4Addr::new(10, 1, 2, 1)).unwrap();
    let mut ipv4 = Ipv4::new(ethernet.clone(), arp, conf);

    ipv4.send(target_ip, 2, |pkg| {
        pkg.set_payload(&[101, 204]);
    });

    let pkg = read_handle.recv().unwrap();
    let eth_pkg = EthernetPacket::new(&pkg[..]).unwrap();
    assert_eq!(eth_pkg.get_source(), source_mac);
    assert_eq!(eth_pkg.get_destination(), target_mac);
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
    let source_mac = MacAddr::new(9, 0, 0, 4, 0, 0);

    let mut ipv4_listeners = HashMap::new();
    let (tx, rx) = mpsc::channel();
    let ipv4_listener = MockIpv4Listener { tx: tx };
    ipv4_listeners.insert(IpNextHeaderProtocols::Igmp, Box::new(ipv4_listener) as Box<Ipv4Listener>);

    let mut ethernet_listeners = HashMap::new();

    let arp_factory = ArpFactory::new();
    let arp_listener = arp_factory.listener();
    ethernet_listeners.insert(EtherTypes::Arp, Box::new(arp_listener) as Box<EthernetListener>);

    let mut ipv4_factory = Ipv4Factory::new(arp_factory, ipv4_listeners);
    let ipv4_listener = ipv4_factory.listener().unwrap();
    ethernet_listeners.insert(EtherTypes::Ipv4, Box::new(ipv4_listener) as Box<EthernetListener>);

    let (_ethernet, target_mac, inject_handle, _) = ::dummy_ethernet(7, ethernet_listeners);

    let size = EthernetPacket::minimum_packet_size() + Ipv4Packet::minimum_packet_size() + 2;
    let mut buffer = vec![0; size];
    {
        let mut eth_pkg = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        eth_pkg.set_source(source_mac);
        eth_pkg.set_destination(target_mac);
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
