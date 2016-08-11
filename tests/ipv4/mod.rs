use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, mpsc};
use std::collections::HashMap;
use std::time::SystemTime;

use ipnetwork::Ipv4Network;

use pnet::util::MacAddr;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{MutablePacket, Packet};

use rips::ipv4::{Ipv4Listener, Ipv4Rx, Ipv4Tx};
use rips::ethernet::{EthernetListener, EthernetRx};

pub struct MockIpv4Listener {
    pub tx: mpsc::Sender<Vec<u8>>,
}

impl Ipv4Listener for MockIpv4Listener {
    fn recv(&mut self, _time: SystemTime, packet: Ipv4Packet) {
        println!("MockIpv4Listener got a packet!");
        self.tx.send(packet.packet().to_vec()).unwrap();
    }
}

#[test]
fn simple_send() {
    let source_ip = Ipv4Addr::new(10, 1, 2, 3);
    let target_ip = Ipv4Addr::new(10, 1, 2, 2);
    let target_mac = MacAddr::new(9, 0, 0, 4, 0, 0);

    let (mut stack, interface, _, read_handle) = ::dummy_stack(0);

    // Inject an Arp entry so Ipv4 knows where to send
    let mut arp = stack.arp_tx(&interface).unwrap();
    arp.insert(target_ip, target_mac);

    let config = Ipv4Network::new(source_ip, 24).unwrap();
    stack.add_ipv4(&interface, config);

    let mut ipv4_tx = stack.ipv4_tx(target_ip).unwrap();
    ipv4_tx.send(2, IpNextHeaderProtocols::Icmp, |pkg| {
        pkg[0] = 101;
        pkg[1] = 204;
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
fn custom_igmp_recv() {
    let source_ip = Ipv4Addr::new(10, 1, 2, 3);
    let target_ip = Ipv4Addr::new(10, 1, 2, 2);

    let (tx, rx) = mpsc::channel();
    let ipv4_listener = MockIpv4Listener { tx: tx };
    let mut ipv4_ip_listeners = HashMap::new();
    ipv4_ip_listeners.insert(IpNextHeaderProtocols::Igmp,
                             Box::new(ipv4_listener) as Box<Ipv4Listener>);

    let mut ipv4_listeners = HashMap::new();
    ipv4_listeners.insert(target_ip, ipv4_ip_listeners);

    let (mut channel, interface, inject_handle, _) = ::dummy_ethernet(0);
    let ipv4_rx = Ipv4Rx::new(Arc::new(Mutex::new(ipv4_listeners)));
    let ethernet_rx = EthernetRx::new(vec![ipv4_rx]).spawn(channel.1);

    let size = EthernetPacket::minimum_packet_size() + Ipv4Packet::minimum_packet_size() + 2;
    let mut buffer = vec![0; size];
    {
        let mut eth_pkg = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        eth_pkg.set_ethertype(EtherTypes::Ipv4);
        let mut ip_pkg = MutableIpv4Packet::new(eth_pkg.payload_mut()).unwrap();
        ip_pkg.set_header_length(5); // 5 is for no option fields
        ip_pkg.set_total_length(20 + 2);
        ip_pkg.set_source(source_ip);
        ip_pkg.set_destination(target_ip);
        ip_pkg.set_next_level_protocol(IpNextHeaderProtocols::Igmp);
        ip_pkg.set_payload(&[67, 99]);
    }

    inject_handle.send(Ok(buffer.into_boxed_slice())).unwrap();

    let pkg = match rx.recv() {
        Ok(p) => p,
        Err(e) => panic!("NOOO: {}", e),
    };
    let ip_pkg = Ipv4Packet::new(&pkg[..]).unwrap();
    assert_eq!(ip_pkg.get_source(), source_ip);
    assert_eq!(ip_pkg.get_destination(), target_ip);
    assert_eq!(ip_pkg.get_next_level_protocol(),
               IpNextHeaderProtocols::Igmp);
    assert_eq!(ip_pkg.payload(), [67, 99]);
}
