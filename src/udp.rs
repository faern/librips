use std::net::Ipv4Addr;
use std::io;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::SystemTime;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::udp::{MutableUdpPacket, UdpPacket, ipv4_checksum};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{MutablePacket, Packet};

use ipv4::{Ipv4, Ipv4Listener};

pub trait UdpListener: Send {
    fn recv(&mut self, time: SystemTime, packet: &Ipv4Packet) -> bool;
}

pub type UdpListenerLookup = HashMap<u16, Box<UdpListener>>;

pub struct UdpIpv4Listener {
    listeners: Arc<Mutex<UdpListenerLookup>>,
}

impl UdpIpv4Listener {
    pub fn new(listeners: Arc<Mutex<UdpListenerLookup>>) -> UdpIpv4Listener {
        UdpIpv4Listener { listeners: listeners }
    }
}

impl Ipv4Listener for UdpIpv4Listener {
    fn recv(&mut self, time: SystemTime, ip_pkg: Ipv4Packet) {
        let port = {
            let udp_pkg = UdpPacket::new(ip_pkg.payload()).unwrap();
            println!("Udp got a packet with {} bytes!", udp_pkg.payload().len());
            udp_pkg.get_destination()
        };
        let mut listeners = self.listeners.lock().unwrap();
        if let Some(listener) = listeners.get_mut(&port) {
            let _resume = listener.recv(time, &ip_pkg);
            // TODO: When resume turns false, remove this socket.
        } else {
            println!("Udp, no listener for port {:?}", port);
        }
    }
}

/// An Icmp communication struct.
#[derive(Clone)]
pub struct Udp {
    ipv4: Ipv4,
}

impl Udp {
    pub fn new(ipv4: Ipv4) -> Udp {
        Udp { ipv4: ipv4 }
    }

    pub fn send_to<T>(&mut self,
                      dst_ip: Ipv4Addr,
                      dst_port: u16,
                      payload_size: u16,
                      mut builder: T)
                      -> Option<io::Result<()>>
        where T: FnMut(&mut MutableUdpPacket)
    {
        let total_size = UdpPacket::minimum_packet_size() as u16 + payload_size;
        let mut builder_wrapper = |ip_pkg: &mut MutableIpv4Packet| {
            ip_pkg.set_next_level_protocol(IpNextHeaderProtocols::Udp);

            let src_ip = ip_pkg.get_source();
            let dst_ip = ip_pkg.get_destination();
            let mut udp_pkg = MutableUdpPacket::new(ip_pkg.payload_mut()).unwrap();
            // TODO: We need source port
            udp_pkg.set_destination(dst_port);
            udp_pkg.set_length(total_size);
            builder(&mut udp_pkg);
            // TODO: Set to zero?
            let checksum = ipv4_checksum(&udp_pkg.to_immutable(),
                                         src_ip,
                                         dst_ip,
                                         IpNextHeaderProtocols::Udp);
            udp_pkg.set_checksum(checksum);
        };
        self.ipv4.send(dst_ip, total_size, &mut builder_wrapper)
    }
}
