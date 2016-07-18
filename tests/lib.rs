use std::collections::HashMap;

extern crate pnet;
extern crate rips;

use std::sync::mpsc::{Receiver, Sender};
use std::io;
use std::net::Ipv4Addr;

use pnet::datalink::{dummy, Channel};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::util::MacAddr;

use rips::{Interface, EthernetChannel};
use rips::ethernet::{Ethernet, EthernetListener};
use rips::arp::ArpFactory;
use rips::ipv4::{Ipv4, Ipv4Factory, Ipv4Listener, Ipv4Config};
use rips::icmp::IcmpListenerFactory;

// Modules containing tests.
mod ethernet;
//mod stack;
mod arp;
mod ipv4;
mod icmp;

fn dummy_ethernet(iface_i: u8, listeners: Vec<Box<EthernetListener>>)
                  -> (Ethernet, MacAddr, Sender<io::Result<Box<[u8]>>>, Receiver<Box<[u8]>>) {
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
    let ethernet = Ethernet::new(interface, channel, listeners);

    (ethernet, mac, inject_handle, read_handle)
}

fn dummy_ipv4(listeners: HashMap<IpNextHeaderProtocol, Box<Ipv4Listener>>) -> (Ethernet, Ipv4Factory, Sender<io::Result<Box<[u8]>>>, Receiver<Box<[u8]>>) {
    let arp_factory = ArpFactory::new();
    let arp_listener = arp_factory.listener();
    let mut ipv4_factory = Ipv4Factory::new(arp_factory, listeners);
    let ipv4_listener = ipv4_factory.listener().unwrap();
    let ethernet_listeners = vec![arp_listener, ipv4_listener];

    let (ethernet, _, inject_handle, read_handle) = dummy_ethernet(0, ethernet_listeners);
    (ethernet, ipv4_factory, inject_handle, read_handle)
}

fn dummy_icmp() -> (Ethernet, IcmpListenerFactory, Ipv4, Sender<io::Result<Box<[u8]>>>, Receiver<Box<[u8]>>) {
    let mut ipv4_listeners = HashMap::new();
    let icmp_factory = IcmpListenerFactory::new();
    let icmp_listener = icmp_factory.ipv4_listener();
    ipv4_listeners.insert(IpNextHeaderProtocols::Icmp, icmp_listener);

    let (ethernet, ipv4_factory, inject_handle, read_handle) = dummy_ipv4(ipv4_listeners);

    let mut arp = ipv4_factory.arp_factory().arp(ethernet.clone());
    arp.insert(Ipv4Addr::new(10, 0, 0, 1), MacAddr::new(9, 8, 7, 6, 5, 4));

    let ip_config = Ipv4Config::new(Ipv4Addr::new(10, 0, 0, 2), 24, Ipv4Addr::new(10, 0, 0, 1)).unwrap();
    let ipv4 = ipv4_factory.ip(ethernet.clone(), ip_config);


    (ethernet, icmp_factory, ipv4, inject_handle, read_handle)
}
