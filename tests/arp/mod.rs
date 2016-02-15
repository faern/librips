use std::sync::mpsc;
use std::thread::{spawn, sleep};
use std::time::Duration;
use std::net::Ipv4Addr;

use pnet::util::MacAddr;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{Packet, MutablePacket};

use pnet_packets::arp::{ArpEthernetIpv4Packet, MutableArpEthernetIpv4Packet};

use rips::NetworkStackBuilder;
use rips::ethernet::EthernetProvider;

use mockpnet::{MockPnet, dummy_iface};

#[test]
fn test_arp_locking() {
    let thread_count = 100;

    let (tx, network_output) = mpsc::channel();
    let (network_input, rx) = mpsc::channel();
    let mut mock_pnet = MockPnet::new(Some(rx), Some(tx));

    let mut stack = NetworkStackBuilder::new()
        .set_provider(&mut mock_pnet as &mut EthernetProvider)
        .set_interfaces(vec![dummy_iface(0)])
        .create()
        .expect("Expected a working NetworkStack");

    let mut arp = stack.get_arp(&dummy_iface(0)).expect("Expected Arp");

    let (arp_thread_tx, arp_thread_rx) = mpsc::channel();
    // Spawn `thread_count` threads that all try to request the same ip
    for _ in 0..thread_count {
        let mut arp = arp.clone();
        let arp_thread_tx = arp_thread_tx.clone();
        spawn(move || {
            let mac = arp.get(&Ipv4Addr::new(10, 0, 0, 99), &Ipv4Addr::new(10, 0, 0, 1));
            arp_thread_tx.send(mac).expect("Unable to send mac to channel");
        });
    }
    sleep(Duration::new(0, 1_000_000));

    // Make sure no one returned yet since no response has been sent
    assert!(arp_thread_rx.try_recv().is_err());

    // Check that the request was sent to the network
    let arp_request_u8 = network_output.recv().unwrap();
    let arp_request_eth = EthernetPacket::new(&arp_request_u8[..]).unwrap();
    let arp_request = ArpEthernetIpv4Packet::new(arp_request_eth.payload()).unwrap();
    let sender_ip = arp_request.get_sender_ip();
    let sender_mac = arp_request.get_sender_mac();
    assert_eq!(Ipv4Addr::new(10, 0, 0, 99), sender_ip);
    assert_eq!(MacAddr::new(1, 2, 3, 4, 5, 6), sender_mac);

    // Send the response back to librips
    let mut buffer = vec![0; EthernetPacket::minimum_packet_size() +
                             ArpEthernetIpv4Packet::minimum_packet_size()];
    {
        let mut eth_pkg = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        eth_pkg.set_ethertype(EtherTypes::Arp);
        {
            let mut arp_pkg = MutableArpEthernetIpv4Packet::new(eth_pkg.payload_mut()).unwrap();
            arp_pkg.set_sender_mac(MacAddr::new(9, 8, 7, 6, 5, 4));
            arp_pkg.set_sender_ip(Ipv4Addr::new(10, 0, 0, 1));
        }
    }
    network_input.send(Ok(buffer.into_boxed_slice())).unwrap();

    // Wait for a short time so threads can react
    sleep(Duration::new(0, 1_000_000));

    // Make sure all threads returned already, otherwise too slow
    for _ in 0..thread_count {
        let mac = arp_thread_rx.recv().expect("Arp thread did not return yet, too slow!");
        assert_eq!(MacAddr::new(9, 8, 7, 6, 5, 4), mac);
    }

    let mac = arp.get(&Ipv4Addr::new(10, 0, 0, 40), &Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(MacAddr::new(9, 8, 7, 6, 5, 4), mac);
}
