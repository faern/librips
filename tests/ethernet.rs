// use pnet::packet::Packet;
// use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
// use pnet::util::MacAddr;
// use rips::ethernet::{EthernetTx, EthernetTxImpl};

// use rips::ethernet::BasicEthernetPayload;
// use rips::testing;

// #[test]
// fn test_ethernet_send() {
//     let src = MacAddr::new(1, 2, 3, 4, 5, 99);
//     let dst = MacAddr::new(6, 7, 8, 9, 10, 11);
//     let (channel, _, _, read_handle) = testing::dummy_ethernet(99);
//     let tx = TxBarrier::new(channel.0);
//     let mut ethernet_tx = EthernetTxImpl::new(tx, src, dst);

// ethernet_tx.send(1, 1, BasicEthernetPayload::new(EtherTypes::Rarp,
// vec![57])).unwrap();

//     let sent_buffer = read_handle.try_recv().unwrap();
//     assert_eq!(sent_buffer.len(), 15);
//     let sent_pkg = EthernetPacket::new(&sent_buffer[..]).unwrap();
//     assert_eq!(sent_pkg.get_source(), src);
//     assert_eq!(sent_pkg.get_destination(), dst);
//     assert_eq!(sent_pkg.get_ethertype(), EtherTypes::Rarp);
//     assert_eq!(sent_pkg.payload()[0], 57);
// }
