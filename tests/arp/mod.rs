use std::sync::{Arc, Mutex, mpsc};
use std::thread::{sleep, spawn};
use std::time::Duration;
use std::net::Ipv4Addr;
use std::io;

use pnet::util::MacAddr;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::packet::arp::{ArpPacket, MutableArpPacket};

use rips::{Tx, VersionedTx};
use rips::arp::{ArpTable, ArpTx};
use rips::ethernet::{EthernetRx, EthernetTx};

use helper;

#[test]
fn arp_invalidate_on_update() {
    let arp_table = ArpTable::new();
    let (channel, _, inject_handle, _) = helper::dummy_ethernet(7);

    let vtx = Arc::new(Mutex::new(VersionedTx::new(channel.0)));
    EthernetRx::new(vec![arp_table.arp_rx(vtx.clone())]).spawn(channel.1);

    let tx = Tx::versioned(vtx);
    let ethernet_tx = EthernetTx::new(tx,
                                      MacAddr::new(0, 0, 0, 0, 0, 0),
                                      MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
    let mut arp = ArpTx::new(ethernet_tx);

    // Send should work before table is updated
    assert!(arp.send(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 0)).is_ok());
    // Inject Arp packet and wait for processing
    send_arp(inject_handle);
    sleep(Duration::new(1, 0));
    // Send should not work after incoming packet bumped VersionedTx revision
    assert!(arp.send(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 0)).is_err());
}

#[test]
fn arp_locking() {
    let thread_count = 100;
    let dst = Ipv4Addr::new(10, 0, 0, 1);

    let arp_table = ArpTable::new();
    let (channel, _, inject_handle, read_handle) = helper::dummy_ethernet(7);
    let vtx = Arc::new(Mutex::new(VersionedTx::new(channel.0)));
    EthernetRx::new(vec![arp_table.arp_rx(vtx.clone())]).spawn(channel.1);

    let (arp_thread_tx, arp_thread_rx) = mpsc::channel();
    // Spawn `thread_count` threads that all try to request the same ip
    for _ in 0..thread_count {
        let mut thread_arp_table = arp_table.clone();
        let arp_thread_tx = arp_thread_tx.clone();
        spawn(move || {
            let mac = match thread_arp_table.get(dst) {
                Ok(mac) => mac,
                Err(rx) => rx.recv().unwrap()
            };
            arp_thread_tx.send(mac).expect("Unable to send mac to channel");
        });
    }
    // Send out the request to the network
    let tx = Tx::versioned(vtx.clone());
    let ethernet_tx = EthernetTx::new(tx,
                                      MacAddr::new(1, 2, 3, 4, 5, 7),
                                      MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
    let mut arp_tx = ArpTx::new(ethernet_tx);
    arp_tx.send(Ipv4Addr::new(10, 0, 0, 34), dst).unwrap();

    sleep(Duration::new(1, 0));

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
    send_arp(inject_handle);
    sleep(Duration::new(1, 0));

    // Make sure all threads returned already, otherwise too slow
    for _ in 0..thread_count {
        let mac = arp_thread_rx.try_recv().expect("Arp thread did not return yet");
        assert_eq!(MacAddr::new(9, 8, 7, 6, 5, 4), mac);
    }
    assert!(arp_thread_rx.try_recv().is_err());
}

fn send_arp(inject_handle: mpsc::Sender<io::Result<Box<[u8]>>>) {
    // Send the response back to librips
    let mut buffer = vec![0; EthernetPacket::minimum_packet_size() +
                             ArpPacket::minimum_packet_size()];
    {
        let mut eth_pkg = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        eth_pkg.set_ethertype(EtherTypes::Arp);
        let mut arp_pkg = MutableArpPacket::new(eth_pkg.payload_mut()).unwrap();
        arp_pkg.set_sender_hw_addr(MacAddr::new(9, 8, 7, 6, 5, 4));
        arp_pkg.set_sender_proto_addr(Ipv4Addr::new(10, 0, 0, 1));
    }
    inject_handle.send(Ok(buffer.into_boxed_slice())).unwrap();
}
