extern crate pnet;
extern crate ipnetwork;
extern crate rips;

#[cfg(all(test, not(feature = "unit-tests")))]
mod ethernet;
// mod stack;
#[cfg(all(test, not(feature = "unit-tests")))]
mod arp;
#[cfg(all(test, not(feature = "unit-tests")))]
mod ipv4;
// mod icmp;
#[cfg(all(test, not(feature = "unit-tests")))]
mod udp;

#[cfg(all(test, not(feature = "unit-tests")))]
mod helper {
    use std::collections::HashMap;
    use std::sync::mpsc::{Receiver, Sender};
    use std::io;

    use pnet::datalink::{Channel, dummy};

    use rips::{EthernetChannel, Interface, NetworkStack};

    pub fn dummy_ethernet
        (iface_i: u8)
         -> (EthernetChannel, Interface, Sender<io::Result<Box<[u8]>>>, Receiver<Box<[u8]>>) {
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

        (channel, interface, inject_handle, read_handle)
    }

    pub fn dummy_stack
        (iface_i: u8)
         -> (NetworkStack, Interface, Sender<io::Result<Box<[u8]>>>, Receiver<Box<[u8]>>) {
        let (channel, interface, inject_handle, read_handle) = dummy_ethernet(iface_i);
        let mut stack = NetworkStack::new();
        stack.add_channel(interface.clone(), channel)
            .expect("Not able to add dummy channel to stack");
        (stack, interface, inject_handle, read_handle)
    }

    // pub fn dummy_icmp()
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
    // let ip_config = Ipv4Config::new(Ipv4Addr::new(10, 0, 0, 2), 24,
    // Ipv4Addr::new(10, 0, 0, 1))
    //         .unwrap();
    //     let ipv4 = Ipv4::new(ethernet.clone(), arp, ip_config);
    //
    //
    //     (ethernet, icmp_listeners, ipv4, inject_handle, read_handle)
    // }
}
