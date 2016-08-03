use std::collections::HashMap;

extern crate pnet;
extern crate rips;

use std::sync::mpsc::{Receiver, Sender};
use std::io;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use pnet::datalink::{Channel, dummy};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::util::MacAddr;

use rips::{EthernetChannel, Interface, VersionedTx};
use rips::ethernet::{EthernetRx, EthernetListener};
// use rips::arp::ArpFactory;
// use rips::ipv4::{IpListenerLookup, Ipv4Tx, Ipv4Config, Ipv4EthernetListener};
// use rips::icmp::{IcmpIpv4Listener, IcmpListenerLookup};

// Modules containing tests.
mod ethernet;
// mod stack;
//mod arp;
//mod ipv4;
//mod icmp;

fn dummy_ethernet(iface_i: u8,
                  listeners: Vec<Box<EthernetListener>>)
                  -> (VersionedTx, MacAddr, Sender<io::Result<Box<[u8]>>>, Receiver<Box<[u8]>>) {
    let iface = dummy::dummy_interface(iface_i);
    let mac = iface.mac.unwrap();
    let interface = Interface {
        name: iface.name.clone(),
        mac: mac,
    };

    let mut config = dummy::Config::default();
    let read_handle = config.read_handle().unwrap();
    let inject_handle = config.inject_handle().unwrap();

    let channel = match dummy::channel(&iface, config).unwrap() {
        Channel::Ethernet(tx, rx) => EthernetChannel(tx, rx),
        _ => panic!("Invalid channel type returned"),
    };
    let tx = VersionedTx::new(channel.0);
    EthernetRx::new(listeners).spawn(channel.1);

    (tx, mac, inject_handle, read_handle)
}

// fn dummy_ipv4(listeners: Arc<Mutex<IpListenerLookup>>)
//               -> (Ethernet, ArpFactory, Sender<io::Result<Box<[u8]>>>, Receiver<Box<[u8]>>) {
//     let arp_factory = ArpFactory::new();
//     let arp_listener = arp_factory.listener();
//
//     let ipv4_listener = Ipv4EthernetListener::new(listeners);
//     let ethernet_listeners = vec![arp_listener, ipv4_listener];
//
//     let (ethernet, _, inject_handle, read_handle) = dummy_ethernet(0, ethernet_listeners);
//     (ethernet, arp_factory, inject_handle, read_handle)
// }
//
// fn dummy_icmp()
//     -> (Ethernet,
//         Arc<Mutex<IcmpListenerLookup>>,
//         Ipv4,
//         Sender<io::Result<Box<[u8]>>>,
//         Receiver<Box<[u8]>>)
// {
//     let icmp_listeners = Arc::new(Mutex::new(HashMap::new()));
//     let icmp_listener = IcmpIpv4Listener::new(icmp_listeners.clone());
//
//     let mut ipv4_ip_listeners = HashMap::new();
//     ipv4_ip_listeners.insert(IpNextHeaderProtocols::Icmp, icmp_listener);
//
//     let mut ipv4_listeners = HashMap::new();
//     ipv4_listeners.insert(Ipv4Addr::new(10, 0, 0, 2), ipv4_ip_listeners);
//
//     let (ethernet, arp_factory, inject_handle, read_handle) =
//         dummy_ipv4(Arc::new(Mutex::new(ipv4_listeners)));
//
//     let mut arp = arp_factory.arp(ethernet.clone());
//     arp.insert(Ipv4Addr::new(10, 0, 0, 1), MacAddr::new(9, 8, 7, 6, 5, 4));
//
//     let ip_config = Ipv4Config::new(Ipv4Addr::new(10, 0, 0, 2), 24, Ipv4Addr::new(10, 0, 0, 1))
//         .unwrap();
//     let ipv4 = Ipv4::new(ethernet.clone(), arp, ip_config);
//
//
//     (ethernet, icmp_listeners, ipv4, inject_handle, read_handle)
// }
