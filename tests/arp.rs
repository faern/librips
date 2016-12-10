extern crate pnet;
extern crate ipnetwork;
extern crate rips;

use ipnetwork::Ipv4Network;

use pnet::packet::{MutablePacket, Packet};
use pnet::packet::arp::{ArpPacket, MutableArpPacket, ArpOperations};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;

use rips::testing;

use std::io;
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[test]
fn arp_invalidate_on_update() {
    let (mut stack, interface, inject_handle, _) = testing::dummy_stack(7);
    let stack_interface = stack.interface(&interface).unwrap();

    let mut arp_request_tx = stack_interface.arp_request_tx();

    // Send should work before table is updated
    assert!(arp_request_tx.send(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 0)).is_ok());
    // Inject Arp packet and wait for processing
    send_arp_reply(inject_handle);
    thread::sleep(Duration::new(1, 0));
    // Send should not work after incoming packet bumped VersionedTx revision
    assert!(arp_request_tx.send(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 0)).is_err());
}

#[test]
fn arp_reply_to_request() {
    let (mut stack, interface, inject_handle, read_handle) = testing::dummy_stack(7);

    let config = Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 1), 24).unwrap();
    stack.add_ipv4(&interface, config).unwrap();

    send_arp_request(inject_handle);
    thread::sleep(Duration::new(1, 0));

    let arp_request_u8 = read_handle.try_recv().unwrap();
    let arp_request_eth = EthernetPacket::new(&arp_request_u8[..]).unwrap();
    let arp_request = ArpPacket::new(arp_request_eth.payload()).unwrap();
    assert_eq!(ArpOperations::Reply, arp_request.get_operation());
}

#[test]
fn arp_locking() {
    let thread_count = 100;
    let dst = Ipv4Addr::new(10, 0, 0, 1);

    let (mut stack, interface, inject_handle, read_handle) = testing::dummy_stack(7);
    let stack_interface = stack.interface(&interface).unwrap();

    let arp_table = stack_interface.arp_table().clone();
    let mut arp_request_tx = stack_interface.arp_request_tx();

    let (arp_thread_tx, arp_thread_rx) = mpsc::channel();
    // Spawn `thread_count` threads that all try to request the same ip
    for _ in 0..thread_count {
        let mut thread_arp_table = arp_table.clone();
        let arp_thread_tx = arp_thread_tx.clone();
        thread::spawn(move || {
            let mac = match thread_arp_table.get(dst) {
                Ok(mac) => mac,
                Err(rx) => rx.recv().unwrap(),
            };
            arp_thread_tx.send(mac).expect("Unable to send mac to channel");
        });
    }
    // Send out the request to the network
    arp_request_tx.send(Ipv4Addr::new(10, 0, 0, 34), dst).unwrap();

    thread::sleep(Duration::new(1, 0));

    // Make sure no one returned yet since no response has been sent
    assert!(arp_thread_rx.try_recv().is_err());

    // Check that the request was sent to the network
    let arp_request_u8 = read_handle.recv().unwrap();
    let arp_request_eth = EthernetPacket::new(&arp_request_u8[..]).unwrap();
    let arp_request = ArpPacket::new(arp_request_eth.payload()).unwrap();
    assert_eq!(MacAddr::new(1, 2, 3, 4, 5, 7),
               arp_request.get_sender_hw_addr());
    assert_eq!(Ipv4Addr::new(10, 0, 0, 1),
               arp_request.get_target_proto_addr());

    // Inject Arp packet and wait for processing
    send_arp_reply(inject_handle);
    thread::sleep(Duration::new(1, 0));

    // Make sure all threads returned already, otherwise too slow
    for _ in 0..thread_count {
        let mac = arp_thread_rx.try_recv().expect("Arp thread did not return yet");
        assert_eq!(MacAddr::new(9, 8, 7, 6, 5, 4), mac);
    }
    assert!(arp_thread_rx.try_recv().is_err());
}

fn send_arp_reply(inject_handle: mpsc::Sender<io::Result<Box<[u8]>>>) {
    // Send the response back to librips
    let mut buffer = vec![0; EthernetPacket::minimum_packet_size() +
                             ArpPacket::minimum_packet_size()];
    {
        let mut eth_pkg = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        eth_pkg.set_ethertype(EtherTypes::Arp);
        let mut arp_pkg = MutableArpPacket::new(eth_pkg.payload_mut()).unwrap();
        arp_pkg.set_operation(ArpOperations::Reply);
        arp_pkg.set_sender_hw_addr(MacAddr::new(9, 8, 7, 6, 5, 4));
        arp_pkg.set_sender_proto_addr(Ipv4Addr::new(10, 0, 0, 1));
    }
    inject_handle.send(Ok(buffer.into_boxed_slice())).unwrap();
}

fn send_arp_request(inject_handle: mpsc::Sender<io::Result<Box<[u8]>>>) {
    let mut buffer = vec![0; EthernetPacket::minimum_packet_size() +
                             ArpPacket::minimum_packet_size()];
    {
        let mut eth_pkg = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        eth_pkg.set_ethertype(EtherTypes::Arp);
        let mut arp_pkg = MutableArpPacket::new(eth_pkg.payload_mut()).unwrap();
        arp_pkg.set_operation(ArpOperations::Request);
        arp_pkg.set_sender_hw_addr(MacAddr::new(9, 8, 7, 6, 5, 4));
        arp_pkg.set_sender_proto_addr(Ipv4Addr::new(10, 0, 0, 2));
        arp_pkg.set_target_proto_addr(Ipv4Addr::new(10, 0, 0, 1));
    }
    inject_handle.send(Ok(buffer.into_boxed_slice())).unwrap();
}
