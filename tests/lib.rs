use std::collections::HashMap;

extern crate pnet;
extern crate rips;
extern crate pnet_packets;

// Modules containing tests.
mod ethernet;
//mod stack;
mod arp;
//mod ipv4;
//mod icmp;

use std::sync::mpsc::{Receiver, Sender};
use std::io;

use pnet::datalink::dummy;
use pnet::packet::ethernet::EtherType;
use pnet::util::MacAddr;

use rips::ethernet::{Ethernet, EthernetListener};

fn dummy_ethernet(iface_i: u8, listeners: HashMap<EtherType, Box<EthernetListener>>)
                  -> (Ethernet, MacAddr, Sender<io::Result<Box<[u8]>>>, Receiver<Box<[u8]>>) {
    let iface = dummy::dummy_interface(iface_i);
    let mac = iface.mac.unwrap();

    let mut config = dummy::Config::default();
    let read_handle = config.read_handle().unwrap();
    let inject_handle = config.inject_handle().unwrap();

    let channel = dummy::channel(&iface, config).unwrap();
    let ethernet = Ethernet::new(mac, channel, listeners);

    (ethernet, mac, inject_handle, read_handle)
}
