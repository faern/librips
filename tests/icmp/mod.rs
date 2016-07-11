use std::net::Ipv4Addr;

use pnet::util::MacAddr;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::icmp::echo_request::EchoRequestPacket;
use pnet::packet::icmp::icmp_types;
use pnet::packet::Packet;

use rips::arp::Arp;
use rips::ipv4::{Ipv4, Ipv4Config};
use rips::icmp::{Icmp, Echo};

#[test]
fn test_ping() {
    let source_ip = Ipv4Addr::new(10, 1, 2, 3);
    let target_ip = Ipv4Addr::new(10, 1, 2, 2);
    let target_mac = MacAddr::new(9, 0, 0, 4, 0, 0);

    let (ethernet, _, _, read_handle) = ::dummy_ethernet(7);

    let mut arp = Arp::new(ethernet.clone());
    arp.insert(target_ip, target_mac);

    let ip_config = Ipv4Config::new(source_ip, 24, Ipv4Addr::new(10, 1, 2, 1)).unwrap();
    let ipv4 = Ipv4::new(ethernet, arp, ip_config);

    let icmp = Icmp::new(ipv4);
    let mut echo = Echo::new(icmp);

    echo.send(target_ip, &[9, 55]).unwrap().unwrap();

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
