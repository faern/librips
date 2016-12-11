extern crate pnet;
extern crate ipnetwork;
extern crate rips;

use ipnetwork::Ipv4Network;

use pnet::packet::MutablePacket;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet, checksum};
use pnet::packet::udp::MutableUdpPacket;

use rips::testing;
use rips::udp::UdpSocket;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

#[test]
fn socket_listen() {
    let source_ip = Ipv4Addr::new(9, 8, 7, 6);
    let target_ip = Ipv4Addr::new(10, 9, 0, 254);

    let (mut stack, interface, inject_handle, _) = testing::dummy_stack();
    stack.add_ipv4(&interface, Ipv4Network::from_str("10.9.0.254/16").unwrap()).unwrap();
    let stack = Arc::new(Mutex::new(stack));

    let socket = UdpSocket::bind(stack, "10.9.0.254:1024").unwrap();

    let mut buffer = vec![0; 100];
    {
        let mut eth_pkg = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        eth_pkg.set_ethertype(EtherTypes::Ipv4);
        let mut ip_pkg = MutableIpv4Packet::new(eth_pkg.payload_mut()).unwrap();
        ip_pkg.set_header_length(5); // 5 is for no option fields
        ip_pkg.set_total_length(20 + 8 + 4);
        ip_pkg.set_source(source_ip);
        ip_pkg.set_destination(target_ip);
        ip_pkg.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        let csum = checksum(&ip_pkg.to_immutable());
        ip_pkg.set_checksum(csum);
        let mut udp_pkg = MutableUdpPacket::new(ip_pkg.payload_mut()).unwrap();
        udp_pkg.set_source(9999);
        udp_pkg.set_destination(1024);
        udp_pkg.set_length(8 + 4);
        udp_pkg.set_payload(&[5, 6, 7, 8]);
    }
    inject_handle.send(Ok(buffer.into_boxed_slice())).unwrap();

    let mut buffer = vec![0; 4];
    let (len, from) = socket.recv_from(&mut buffer[..]).unwrap();
    assert_eq!(from, SocketAddr::V4(SocketAddrV4::new(source_ip, 9999)));
    assert_eq!(len, 4);
    assert_eq!(&buffer, &[5, 6, 7, 8]);

}
