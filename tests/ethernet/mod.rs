use pnet::packet::{Packet, PrimitiveValues};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;

use rips::ethernet::{BasicEthernetProtocol, BasicEthernetListener};
use rips::ethernet::{EthernetRx, EthernetTx, EthernetTxImpl};
use rips::rx;
use rips::testing;
use rips::tx::TxBarrier;

use std::sync::mpsc;

#[test]
fn test_ethernet_recv() {
    let (listener_tx, listener_rx) = mpsc::channel();
    let mock_listener = BasicEthernetListener::new(EtherTypes::Arp, listener_tx);

    let (channel, _, inject_handle, _) = testing::dummy_ethernet(0);
    let ethernet_rx = EthernetRx::new(vec![mock_listener]);
    rx::spawn(channel.1, ethernet_rx);

    let mut buffer = vec![0; EthernetPacket::minimum_packet_size() + 3];
    {
        let mut eth_packet = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        eth_packet.set_source(MacAddr::new(1, 2, 3, 4, 5, 6));
        eth_packet.set_destination(MacAddr::new(9, 8, 7, 6, 5, 4));
        eth_packet.set_ethertype(EtherTypes::Arp);
        eth_packet.set_payload(&[15, 16, 17]);
    }

    inject_handle.send(Ok(buffer.into_boxed_slice())).unwrap();
    let (_time, eth_packet) = listener_rx.recv().unwrap();
    assert_eq!((1, 2, 3, 4, 5, 6),
               eth_packet.get_source().to_primitive_values());
    assert_eq!((9, 8, 7, 6, 5, 4),
               eth_packet.get_destination().to_primitive_values());
    assert_eq!(0x0806, eth_packet.get_ethertype().to_primitive_values().0);
    assert_eq!(&[15, 16, 17], eth_packet.payload());
}

#[test]
fn test_ethernet_send() {
    let src = MacAddr::new(1, 2, 3, 4, 5, 99);
    let dst = MacAddr::new(6, 7, 8, 9, 10, 11);
    let (channel, _, _, read_handle) = testing::dummy_ethernet(99);
    let tx = TxBarrier::new(channel.0);
    let mut ethernet_tx = EthernetTxImpl::new(tx, src, dst);

    ethernet_tx.send(1, 1, BasicEthernetProtocol::new(EtherTypes::Rarp, vec![57]))
        .expect("Unable to send to ethernet");

    let sent_buffer = read_handle.try_recv().expect("Expected a packet to have been sent");
    assert_eq!(sent_buffer.len(), 15);
    let sent_pkg = EthernetPacket::new(&sent_buffer[..]).expect("Expected buffer to fit a frame");
    assert_eq!(sent_pkg.get_source(), src);
    assert_eq!(sent_pkg.get_destination(), dst);
    assert_eq!(sent_pkg.get_ethertype(), EtherTypes::Rarp);
    assert_eq!(sent_pkg.payload()[0], 57);
}
