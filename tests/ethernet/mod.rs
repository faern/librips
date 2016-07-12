use std::sync::mpsc;

use pnet::packet::ethernet::{EtherTypes, EtherType, MutableEthernetPacket, EthernetPacket};
use pnet::util::MacAddr;
use pnet::packet::{Packet, PrimitiveValues};

use rips::ethernet::EthernetListener;

pub struct MockEthernetListener {
    pub tx: mpsc::Sender<Vec<u8>>,
}

impl EthernetListener for MockEthernetListener {
    fn recv(&mut self, packet: &EthernetPacket) {
        self.tx.send(packet.packet().to_vec()).unwrap();
    }

    fn get_ethertype(&self) -> EtherType {
        EtherTypes::Arp
    }
}

#[test]
fn test_ethernet_recv() {
    let (listener_tx, listener_rx) = mpsc::channel();
    let mock_listener = MockEthernetListener { tx: listener_tx };
    let listeners = vec![Box::new(mock_listener) as Box<EthernetListener>];

    let (_ethernet, _, inject_handle, _) = ::dummy_ethernet(0, listeners);

    let mut buffer = vec![0; EthernetPacket::minimum_packet_size() + 3];
    {
        let mut eth_packet = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        eth_packet.set_source(MacAddr::new(1, 2, 3, 4, 5, 6));
        eth_packet.set_destination(MacAddr::new(9, 8, 7, 6, 5, 4));
        eth_packet.set_ethertype(EtherTypes::Arp);
        eth_packet.set_payload(&[15, 16, 17]);
    }

    inject_handle.send(Ok(buffer.into_boxed_slice())).unwrap();
    let packet = listener_rx.recv().unwrap();
    let eth_packet = EthernetPacket::new(&packet[..]).unwrap();
    assert_eq!((1, 2, 3, 4, 5, 6),
               eth_packet.get_source().to_primitive_values());
    assert_eq!((9, 8, 7, 6, 5, 4),
               eth_packet.get_destination().to_primitive_values());
    assert_eq!(0x0806, eth_packet.get_ethertype().to_primitive_values().0);
    assert_eq!(&[15, 16, 17], eth_packet.payload());
}

#[test]
fn test_ethernet_send() {
    let (mut ethernet, _, _, read_handle) = ::dummy_ethernet(99, vec![]);

    ethernet.send(1, 1, |pkg| {
        pkg.set_destination(MacAddr::new(6, 7, 8, 9, 10, 11));
        pkg.set_ethertype(EtherTypes::Rarp);
        pkg.set_payload(&[57]);
    });

    let sent_buffer = read_handle.recv().expect("Expected a packet to have been sent");
    assert_eq!(15, sent_buffer.len());
    let sent_pkg = EthernetPacket::new(&sent_buffer[..]).expect("Expected buffer to fit a frame");
    assert_eq!((1, 2, 3, 4, 5, 99),
               sent_pkg.get_source().to_primitive_values());
    assert_eq!((6, 7, 8, 9, 10, 11),
               sent_pkg.get_destination().to_primitive_values());
    assert_eq!(0x8035, sent_pkg.get_ethertype().to_primitive_values().0);
    assert_eq!(57, sent_pkg.payload()[0]);
}
