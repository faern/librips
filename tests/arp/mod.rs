use std::sync::mpsc;
use std::thread::{spawn, sleep};
use std::time::Duration;
use std::net::Ipv4Addr;

use pnet::util::MacAddr;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{Packet, MutablePacket};
use pnet::datalink::dummy;

use pnet_packets::arp::{ArpEthernetIpv4Packet, MutableArpEthernetIpv4Packet};

use rips::NetworkStack;
use rips::ethernet::Ethernet;

#[test]
fn test_arp_locking() {
    let thread_count = 100;

    let iface = dummy::dummy_interface(7);
    let mac = iface.mac.unwrap();
    let mut config = dummy::Config::default();
    let inject_handle = config.inject_handle().unwrap();
    let read_handle = config.read_handle().unwrap();
    let channel = dummy::channel(&iface, config).unwrap();
    let eth = Ethernet::new(mac, channel);
    let stack = NetworkStack::new(&[eth]);

    let arp = stack.get_arp(mac).expect("Expected Arp");

    let (arp_thread_tx, arp_thread_rx) = mpsc::channel();
    // Spawn `thread_count` threads that all try to request the same ip
    for i in 0..thread_count {
        let mut arp = arp.clone();
        let arp_thread_tx = arp_thread_tx.clone();
        spawn(move || {
            let mac = arp.get(Ipv4Addr::new(10, 0, 0, i), Ipv4Addr::new(10, 0, 0, 1));
            arp_thread_tx.send(mac).expect("Unable to send mac to channel");
        });
    }
    sleep(Duration::new(0, 1_000_000));

    // Make sure no one returned yet since no response has been sent
    assert!(arp_thread_rx.try_recv().is_err());

    // Check that the request was sent to the network
    let arp_request_u8 = read_handle.recv().unwrap();
    let arp_request_eth = EthernetPacket::new(&arp_request_u8[..]).unwrap();
    let arp_request = ArpEthernetIpv4Packet::new(arp_request_eth.payload()).unwrap();
    assert_eq!(MacAddr::new(1, 2, 3, 4, 5, 7), arp_request.get_sender_mac());
    assert_eq!(Ipv4Addr::new(10, 0, 0, 1), arp_request.get_target_ip());

    // Send the response back to librips
    let mut buffer = vec![0; EthernetPacket::minimum_packet_size() +
                             ArpEthernetIpv4Packet::minimum_packet_size()];
    {
        let mut eth_pkg = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        eth_pkg.set_ethertype(EtherTypes::Arp);
        let mut arp_pkg = MutableArpEthernetIpv4Packet::new(eth_pkg.payload_mut()).unwrap();
        arp_pkg.set_sender_mac(MacAddr::new(9, 8, 7, 6, 5, 4));
        arp_pkg.set_sender_ip(Ipv4Addr::new(10, 0, 0, 1));
    }
    inject_handle.send(Ok(buffer.into_boxed_slice())).unwrap();

    // Wait for a short time so threads can react
    sleep(Duration::new(0, 1_000_000));

    // Make sure all threads returned already, otherwise too slow
    for _ in 0..thread_count {
        let mac = arp_thread_rx.recv().expect("Arp thread did not return yet, too slow!");
        assert_eq!(MacAddr::new(9, 8, 7, 6, 5, 4), mac);
    }
    assert!(arp_thread_rx.try_recv().is_err());
}
