use std::net::Ipv4Addr;

use pnet::datalink::dummy;
use pnet::util::MacAddr;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

use rips::NetworkStack;
use rips::ethernet::Ethernet;
use rips::ipv4::Ipv4Conf;

#[test]
fn test_simple_send() {
    let source_ip = Ipv4Addr::new(10, 1, 2, 3);
    let target_ip = Ipv4Addr::new(10, 1, 2, 2);
    let target_mac = MacAddr::new(9, 0, 0, 4, 0, 0);

    let iface = dummy::dummy_interface(7);
    let source_mac = iface.mac.unwrap();

    let mut config = dummy::Config::default();
    let read_handle = config.read_handle().unwrap();
    let channel = dummy::channel(&iface, config).unwrap();
    let eth = Ethernet::new(source_mac, channel);
    let mut stack = NetworkStack::new(&[eth]);

    // Inject an Arp entry so Ipv4 knows where to send
    let mut arp = stack.get_arp(source_mac).expect("Expected Arp");
    arp.insert(target_ip, target_mac);

    let ip_config = Ipv4Conf::new(source_ip, 24, Ipv4Addr::new(10, 1, 2, 1))
        .unwrap();
    let mut ipv4 = stack.add_ipv4(source_mac, ip_config).unwrap();

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
