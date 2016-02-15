use std::sync::mpsc;

use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket, EthernetPacket};
use pnet::util::MacAddr;
use pnet::packet::{Packet, PrimitiveValues};

use rips::ethernet::{EthernetProvider, EthernetListener, Ethernet};

use mockpnet::{MockPnet, MockEthernetListener, dummy_iface, dummy_conf};

#[test]
fn test_ethernet_recv() {
    let (input_tx, input_rx) = mpsc::channel();

    let mut mock_pnet = MockPnet::new(Some(input_rx), None);
    let eth = Ethernet::new_with_provider(&mut mock_pnet as &mut EthernetProvider,
                                          &dummy_iface(0),
                                          &dummy_conf())
        .expect("Expected Ethernet to work");

    let (listener_tx, listener_rx) = mpsc::channel();
    let mock_listener = MockEthernetListener { tx: listener_tx };
    eth.set_listener(EtherTypes::Arp, mock_listener);

    let mut buffer = vec![0; EthernetPacket::minimum_packet_size() + 3];
    {
        let mut eth_packet = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        eth_packet.set_source(MacAddr::new(1, 2, 3, 4, 5, 6));
        eth_packet.set_destination(MacAddr::new(9, 8, 7, 6, 5, 4));
        eth_packet.set_ethertype(EtherTypes::Arp);
        eth_packet.set_payload(&[15, 16, 17]);
    }

    input_tx.send(Ok(buffer.into_boxed_slice())).unwrap();
    let packet = listener_rx.recv().unwrap();
    {
        let eth_packet = EthernetPacket::new(&packet[..]).unwrap();
        assert_eq!((1, 2, 3, 4, 5, 6),
                   eth_packet.get_source().to_primitive_values());
        assert_eq!((9, 8, 7, 6, 5, 4),
                   eth_packet.get_destination().to_primitive_values());
        assert_eq!(0x0806, eth_packet.get_ethertype().to_primitive_values().0);
        assert_eq!(&[15, 16, 17], eth_packet.payload());
    }
}

#[test]
fn test_ethernet_send() {
    let (tx, rx) = mpsc::channel();
    let mut mock_pnet = MockPnet::new(None, Some(tx));

    let mut ethernet = Ethernet::new_with_provider(&mut mock_pnet as &mut EthernetProvider,
                                                   &dummy_iface(0),
                                                   &dummy_conf())
        .expect("Expected Ethernet to work");
    ethernet.send(1, 0, |pkg| {
        pkg.set_destination(MacAddr::new(6, 7, 8, 9, 10, 11));
        pkg.set_ethertype(EtherTypes::Rarp);
    });

    let sent_buffer = rx.recv().expect("Expected a packet to have been sent");
    assert_eq!(14, sent_buffer.len());
    let sent_pkg = EthernetPacket::new(&sent_buffer[..]).expect("Expected buffer to fit a frame");
    assert_eq!((1, 2, 3, 4, 5, 6),
               sent_pkg.get_source().to_primitive_values());
    assert_eq!((6, 7, 8, 9, 10, 11),
               sent_pkg.get_destination().to_primitive_values());
    assert_eq!(0x8035, sent_pkg.get_ethertype().to_primitive_values().0);
}
