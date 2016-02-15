use std::sync::mpsc;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::util::MacAddr;
use pnet::packet::PrimitiveValues;

use rips::NetworkStackBuilder;
use rips::ethernet::EthernetProvider;

use mockpnet::{MockPnet, dummy_iface};

#[test]
fn test_networkstack_send_ethernet() {
    let (tx, rx) = mpsc::channel();
    let mut mock_pnet = MockPnet::new(None, Some(tx));

    let mut stack = NetworkStackBuilder::new()
        .set_provider(&mut mock_pnet as &mut EthernetProvider)
        .set_interfaces(vec![dummy_iface(1)])
        .create()
        .expect("Expected a working NetworkStack");

    let mut ethernet = stack.get_ethernet(&dummy_iface(1)).expect("Expected Ethernet");
    ethernet.send(1, 0, |pkg| {
        pkg.set_destination(MacAddr::new(6, 7, 8, 9, 10, 11));
        pkg.set_ethertype(EtherTypes::Ipv4);
    });

    let sent_buffer = rx.recv().expect("Expected a packet to have been sent");
    assert_eq!(14, sent_buffer.len());
    let sent_pkg = EthernetPacket::new(&sent_buffer[..]).expect("Expected buffer to fit a frame");
    assert_eq!((1, 2, 3, 4, 5, 7),
               sent_pkg.get_source().to_primitive_values());
    assert_eq!((6, 7, 8, 9, 10, 11),
               sent_pkg.get_destination().to_primitive_values());
    assert_eq!(0x0800, sent_pkg.get_ethertype().to_primitive_values().0);
}

#[test]
fn test_networkstack_get_invalid_ethernet() {
    let mut mock_pnet = MockPnet::new(None, None);
    let mut stack = NetworkStackBuilder::new()
        .set_provider(&mut mock_pnet as &mut EthernetProvider)
        .set_interfaces(vec![dummy_iface(1)])
        .create()
        .expect("Expected a working NetworkStack");

    let ethernet = stack.get_ethernet(&dummy_iface(2));
    assert!(ethernet.is_none());
}
