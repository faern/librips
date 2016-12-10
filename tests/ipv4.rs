extern crate rips;
extern crate pnet;
extern crate ipnetwork;

use ipnetwork::Ipv4Network;

use pnet::packet::{MutablePacket, Packet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum};
use pnet::util::MacAddr;

use rips::ethernet::EthernetRx;
use rips::ipv4::{BasicIpv4Listener, Ipv4Rx, Ipv4Tx};
use rips::rx;
use rips::testing;
use rips::testing::ipv4::TestIpv4Payload;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

#[test]
fn simple_send() {
    let source_ip = Ipv4Addr::new(10, 1, 2, 3);
    let target_ip = Ipv4Addr::new(10, 1, 2, 2);
    let target_mac = MacAddr::new(9, 0, 0, 4, 0, 0);

    let (mut stack, interface, _, read_handle) = testing::dummy_stack(0);

    // Inject an Arp entry so Ipv4 knows where to send
    stack.interface(&interface).unwrap().arp_table().insert(target_ip, target_mac);

    let config = Ipv4Network::new(source_ip, 24).unwrap();
    stack.add_ipv4(&interface, config).unwrap();

    let mut ipv4_tx = stack.ipv4_tx(target_ip).unwrap();
    ipv4_tx.send(TestIpv4Payload::new(2)).unwrap();

    let pkg = read_handle.recv().unwrap();
    let eth_pkg = EthernetPacket::new(&pkg[..]).unwrap();
    assert_eq!(eth_pkg.get_destination(), target_mac);
    assert_eq!(eth_pkg.get_ethertype(), EtherTypes::Ipv4);
    let ip_pkg = Ipv4Packet::new(eth_pkg.payload()).unwrap();
    assert_eq!(ip_pkg.get_version(), 4);
    assert_eq!(ip_pkg.get_source(), source_ip);
    assert_eq!(ip_pkg.get_destination(), target_ip);
    assert_eq!(ip_pkg.payload(), [100, 99]);
}

#[test]
fn custom_igmp_recv() {
    let source_ip = Ipv4Addr::new(10, 1, 2, 3);
    let target_ip = Ipv4Addr::new(10, 1, 2, 2);

    let (tx, rx) = mpsc::channel();
    let ipv4_listener = BasicIpv4Listener::new(tx);
    let mut ipv4_ip_listeners = HashMap::new();
    ipv4_ip_listeners.insert(IpNextHeaderProtocols::Igmp, ipv4_listener);

    let mut ipv4_listeners = HashMap::new();
    ipv4_listeners.insert(target_ip, ipv4_ip_listeners);

    let (channel, _interface, inject_handle, _) = testing::dummy_ethernet(0);
    let ipv4_rx = Ipv4Rx::new(Arc::new(Mutex::new(ipv4_listeners)));
    let ethernet_rx = EthernetRx::new(vec![ipv4_rx]);
    rx::spawn(channel.1, ethernet_rx);

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
        ip_pkg.set_total_length(20 + 2);
        ip_pkg.set_payload(&[67, 99]);
        let csum = checksum(&ip_pkg.to_immutable());
        ip_pkg.set_checksum(csum);
    }

    inject_handle.send(Ok(buffer.into_boxed_slice())).unwrap();
    thread::sleep(Duration::new(1, 0));

    let (_time, ip_pkg) = rx.try_recv().unwrap();
    assert_eq!(ip_pkg.get_source(), source_ip);
    assert_eq!(ip_pkg.get_destination(), target_ip);
    assert_eq!(ip_pkg.get_next_level_protocol(),
               IpNextHeaderProtocols::Igmp);
    assert_eq!(ip_pkg.payload(), [67, 99]);
}
