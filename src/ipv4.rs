use std::io;
use std::net::Ipv4Addr;
use std::collections::HashMap;
use std::convert::From;
use std::sync::{Arc, Mutex};

use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Packet, checksum};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket, EthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;

use ipnetwork::{self, Ipv4Network};

use ethernet::{Ethernet, EthernetListener};
use arp::Arp;

#[derive(Debug)]
pub enum IpConfError {
    InvalidNetwork(ipnetwork::IpNetworkError),
    IpNotInNetwork,
}

impl From<ipnetwork::IpNetworkError> for IpConfError {
    fn from(e: ipnetwork::IpNetworkError) -> Self {
        IpConfError::InvalidNetwork(e)
    }
}

/// IP settings for one `Ipv4` instance
#[derive(Clone)]
pub struct Ipv4Conf {
    pub ip: Ipv4Addr,
    gw: Ipv4Addr,
    net: Ipv4Network,
}

impl Ipv4Conf {
    /// Creates a new `Ipv4Conf`.
    /// Checks so the gateways is inside the network, returns None otherwise.
    pub fn new(ip: Ipv4Addr, prefix: u8, gw: Ipv4Addr) -> Result<Ipv4Conf, IpConfError> {
        let net = try!(Ipv4Network::new(ip, prefix));
        if !net.contains(gw) {
            Err(IpConfError::IpNotInNetwork)
        } else {
            Ok(Ipv4Conf {
                ip: ip,
                gw: gw,
                net: net,
            })
        }
    }
}

/// Anyone interested in receiving IPv4 packets from `Ipv4` must implement this.
pub trait Ipv4Listener: Send {
    /// Called by the library to deliver an `Ipv4Packet` to a listener.
    fn recv(&mut self, packet: Ipv4Packet);
}

pub struct Ipv4Factory {
    ethernet: Ethernet,
    arp: Arp,
    ipv4s: Arc<Mutex<HashMap<Ipv4Addr, Ipv4>>>,
}

impl Ipv4Factory {
    pub fn new(ethernet: Ethernet) -> Ipv4Factory {
        let arp = Arp::new(ethernet.clone());
        let ipv4s = Arc::new(Mutex::new(HashMap::new()));
        ethernet.set_listener(EtherTypes::Ipv4, Ipv4EthernetListener::new(ipv4s.clone()));
        Ipv4Factory {
            ethernet: ethernet,
            arp: arp,
            ipv4s: ipv4s,
        }
    }

    pub fn get_arp(&self) -> Arp {
        self.arp.clone()
    }

    pub fn add_ip(&self, config: Ipv4Conf) -> Ipv4 {
        let ipv4 = Ipv4::new(self.ethernet.clone(), self.arp.clone(), config);
        let mut ipv4s = self.ipv4s.lock().expect("Unable to lock Ipv4Factory::ipv4s");
        ipv4s.insert(ipv4.conf.ip, ipv4.clone());
        ipv4
    }
}

pub struct Ipv4EthernetListener {
    ipv4s: Arc<Mutex<HashMap<Ipv4Addr, Ipv4>>>,
}

impl Ipv4EthernetListener {
    pub fn new(ipv4s: Arc<Mutex<HashMap<Ipv4Addr, Ipv4>>>) -> Ipv4EthernetListener {
        Ipv4EthernetListener { ipv4s: ipv4s }
    }
}

impl EthernetListener for Ipv4EthernetListener {
    fn recv(&mut self, pkg: EthernetPacket) {
        let ip_pkg = Ipv4Packet::new(pkg.payload()).unwrap();
        let dest_ip = ip_pkg.get_destination();
        println!("Ipv4 got a packet to {}!", dest_ip);
        // Release lock before recv call
        let ipv4 = {
            let ipv4s = self.ipv4s.lock().expect("Unable to lock Ipv4EthernetListener::ipv4s");
            ipv4s.get(&dest_ip).map(|ipv4| ipv4.clone())
        };
        if let Some(mut ipv4) = ipv4 {
            ipv4.recv(ip_pkg);
        }
    }
}

#[derive(Clone)]
pub struct Ipv4 {
    pub conf: Ipv4Conf,
    eth: Ethernet,
    arp: Arp,
    listeners: Arc<Mutex<HashMap<IpNextHeaderProtocol, Box<Ipv4Listener>>>>,
}

impl Ipv4 {
    pub fn new(eth: Ethernet, arp: Arp, conf: Ipv4Conf) -> Ipv4 {
        Ipv4 {
            conf: conf,
            eth: eth,
            arp: arp,
            listeners: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn set_listener<L>(&self, next_protocol: IpNextHeaderProtocol, listener: L)
        where L: Ipv4Listener + 'static
    {
        let mut listeners = self.listeners.lock().expect("Unable to lock Ipv4::listeners");
        listeners.insert(next_protocol, Box::new(listener));
    }

    pub fn send<T>(&mut self,
                   dst_ip: Ipv4Addr,
                   payload_size: u16,
                   mut builder: T)
                   -> Option<io::Result<()>>
        where T: FnMut(&mut MutableIpv4Packet)
    {
        let total_size = Ipv4Packet::minimum_packet_size() as u16 + payload_size;
        // Get destination MAC before locking `eth` since the arp lookup might take time.
        let dst_mac = self.get_dst_mac(dst_ip);
        let src_ip = self.conf.ip;
        let mut builder_wrapper = |eth_pkg: &mut MutableEthernetPacket| {
            eth_pkg.set_destination(dst_mac);
            eth_pkg.set_ethertype(EtherTypes::Ipv4);
            {
                let mut ip_pkg = MutableIpv4Packet::new(eth_pkg.payload_mut()).unwrap();
                ip_pkg.set_version(4);
                ip_pkg.set_header_length(5); // 5 is for no option fields
                ip_pkg.set_dscp(0); // https://en.wikipedia.org/wiki/Differentiated_services
                ip_pkg.set_ecn(0); // https://en.wikipedia.org/wiki/Explicit_Congestion_Notification
                ip_pkg.set_total_length(total_size as u16);
                ip_pkg.set_identification(0); // Use when implementing fragmentation
                ip_pkg.set_flags(0x010); // Hardcoded to DF (don't fragment)
                ip_pkg.set_fragment_offset(0);
                ip_pkg.set_ttl(40);
                ip_pkg.set_source(src_ip);
                ip_pkg.set_destination(dst_ip);
                // ip_pkg.set_options(vec![]); // We currently don't support options in the header
                builder(&mut ip_pkg);
                ip_pkg.set_checksum(0);
                let checksum = checksum(&ip_pkg.to_immutable());
                ip_pkg.set_checksum(checksum);
            }
        };
        self.eth.send(1, total_size as usize, &mut builder_wrapper)
    }

    /// Computes to what MAC to send a packet.
    /// If `ip` is within the local network directly get the MAC, otherwise gateway MAC.
    fn get_dst_mac(&mut self, ip: Ipv4Addr) -> MacAddr {
        let local_dst_ip = if self.conf.net.contains(ip) {
            ip
        } else {
            // Destination outside our network, send to default gateway
            self.conf.gw
        };
        self.arp.get(self.conf.ip, local_dst_ip)
    }

    fn recv(&mut self, pkg: Ipv4Packet) {
        println!("Ipv4 got a packet with {} bytes!", pkg.payload().len());
        let next_level_protocol = pkg.get_next_level_protocol();

        let mut listeners = self.listeners.lock().expect("Unable to lock Ipv4::listeners");
        if let Some(mut listener) = listeners.get_mut(&next_level_protocol) {
            listener.recv(pkg);
        } else {
            println!("Ipv4, no one was listening to {:?} :(", next_level_protocol);
        }
    }
}
