#[allow(unused_imports)]

use std::io;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::net::Ipv4Addr;

use pnet::util::MacAddr;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};

use pnet_packets::arp::{ArpEthernetIpv4Packet, MutableArpEthernetIpv4Packet};

use ethernet::{Ethernet, EthernetListener};

#[derive(Clone)]
struct ArpListener {
    table: Arc<RwLock<HashMap<Ipv4Addr, MacAddr>>>,
    listeners: Arc<Mutex<HashMap<Ipv4Addr, Vec<Sender<MacAddr>>>>>,
}

impl ArpListener {
    pub fn new(table: Arc<RwLock<HashMap<Ipv4Addr, MacAddr>>>) -> ArpListener {
        ArpListener {
            table: table,
            listeners: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add_listener(&mut self, ip: Ipv4Addr) -> Receiver<MacAddr> {
        let (tx, rx) = channel();
        let mut listeners = self.listeners.lock().expect("Unable to lock ArpListener::listeners");
        if !listeners.contains_key(&ip) {
            listeners.insert(ip, vec![]);
        }
        listeners.get_mut(&ip).unwrap().push(tx);
        rx
    }
}

impl EthernetListener for ArpListener {
    fn recv(&mut self, pkg: EthernetPacket) {
        let arp_pkg = ArpEthernetIpv4Packet::new(pkg.payload()).unwrap();
        let ip = arp_pkg.get_sender_ip();
        let mac = arp_pkg.get_sender_mac();
        println!("Arp MAC: {} -> IPv4: {}", mac, ip);
        let mut table = self.table.write().expect("Unable to lock ArpListener::table for writing");
        table.insert(ip, mac);
        let listeners = self.listeners.lock().expect("Unable to lock ArpListener::listeners");
        if let Some(ip_listeners) = listeners.get(&ip) {
            for listener in ip_listeners {
                listener.send(mac).expect("Unable to send MAC to listener");
            }
        }
    }
}

#[derive(Clone)]
pub struct Arp {
    table: Arc<RwLock<HashMap<Ipv4Addr, MacAddr>>>,
    eth: Ethernet,
    arp_listener: ArpListener,
}

impl Arp {
    pub fn new(eth: Ethernet) -> Arp {
        let table = Arc::new(RwLock::new(HashMap::new()));
        let arp_listener = ArpListener::new(table.clone());
        eth.set_listener(EtherTypes::Arp, arp_listener.clone());
        Arp {
            table: table,
            eth: eth,
            arp_listener: arp_listener,
        }
    }

    /// Queries the table for a MAC. If it does not exist a request is sent and the call is blocked
    /// until a reply has arrived
    pub fn get(&mut self, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> MacAddr {
        let mac_rx = {
            let table_arc = self.table.clone(); // Must do this to not borrow self
            let table = table_arc.read().expect("Unable to lock Arp::table for reading");
            if let Some(mac) = table.get(&target_ip) {
                return mac.clone();
            }
            self.send(sender_ip, target_ip)
                .expect("Too small buffer")
                .expect("Network send error");
            self.arp_listener.add_listener(target_ip)
        }; // Release table lock
        mac_rx.recv().expect("Unable to read MAC from mac_rx")
    }

    /// Send Arp packets to the network. More specifically Ipv4 to Ethernet
    pub fn send(&mut self, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Option<io::Result<()>> {
        let local_mac = self.eth.mac;
        let mut builder_wrapper = |eth_pkg: &mut MutableEthernetPacket| {
            eth_pkg.set_destination(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
            eth_pkg.set_ethertype(EtherTypes::Arp);
            {
                let mut arp_pkg = MutableArpEthernetIpv4Packet::new(eth_pkg.payload_mut()).unwrap();
                arp_pkg.set_hardware_type(1);
                arp_pkg.set_protocol_type(EtherTypes::Ipv4);
                arp_pkg.set_hw_addr_len(6);
                arp_pkg.set_protocol_addr_len(4);
                arp_pkg.set_opcode(1);
                arp_pkg.set_sender_mac(local_mac.clone());
                arp_pkg.set_sender_ip(sender_ip.clone());
                arp_pkg.set_target_mac(MacAddr::new(0, 0, 0, 0, 0, 0));
                arp_pkg.set_target_ip(target_ip.clone());
            }
        };
        self.eth.send(1,
                      ArpEthernetIpv4Packet::minimum_packet_size(),
                      &mut builder_wrapper)
    }
}
