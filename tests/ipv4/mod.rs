use std::net::Ipv4Addr;

use pnet::util::MacAddr;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

use rips::arp::Arp;
use rips::ipv4::{Ipv4Conf, Ipv4};

#[test]
fn test_simple_send() {
    let source_ip = Ipv4Addr::new(10, 1, 2, 3);
    let target_ip = Ipv4Addr::new(10, 1, 2, 2);
    let target_mac = MacAddr::new(9, 0, 0, 4, 0, 0);

    let (ethernet, source_mac, _, read_handle) = ::dummy_ethernet(7);

    // Inject an Arp entry so Ipv4 knows where to send
    let mut arp = Arp::new(ethernet.clone());
    arp.insert(target_ip, target_mac);

    let conf = Ipv4Conf::new(source_ip, 24, Ipv4Addr::new(10, 1, 2, 1)).unwrap();
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
