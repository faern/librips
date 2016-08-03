use std::net::{Ipv4Addr, ToSocketAddrs, SocketAddr};
use std::io;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::SystemTime;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::udp::{MutableUdpPacket, UdpPacket, ipv4_checksum};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{MutablePacket, Packet};

use {TxResult, NetworkStack};
use ipv4::{Ipv4Tx, Ipv4Listener};
use util;

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

pub struct UdpTx {
    src: u16,
    dst: u16,
    ipv4: Ipv4Tx,
}

impl UdpTx {
    pub fn new(ipv4: Ipv4Tx, src: u16, dst: u16, rev: u64) -> UdpTx {
        UdpTx {
            src: src,
            dst: dst,
            ipv4: ipv4,
        }
    }

    pub fn send<T>(&mut self,
                   payload_size: u16,
                   mut builder: T)
                   -> TxResult
        where T: FnMut(&mut MutableUdpPacket)
    {
        let total_size = UdpPacket::minimum_packet_size() as u16 + payload_size;
        let mut builder_wrapper = |ip_pkg: &mut MutableIpv4Packet| {
            ip_pkg.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            let src_ip = ip_pkg.get_source();
            let dst_ip = ip_pkg.get_destination();

            let mut udp_pkg = MutableUdpPacket::new(ip_pkg.payload_mut()).unwrap();
            udp_pkg.set_source(self.src);
            udp_pkg.set_destination(self.dst);
            udp_pkg.set_length(total_size);
            builder(&mut udp_pkg);
            // TODO: Set to zero?
            let checksum = ipv4_checksum(&udp_pkg.to_immutable(),
                                         src_ip,
                                         dst_ip,
                                         IpNextHeaderProtocols::Udp);
            udp_pkg.set_checksum(checksum);
        };
        self.ipv4.send(total_size, &mut builder_wrapper)
    }
}

pub struct UdpSocket {
    sender_cache: HashMap<Ipv4Addr, UdpTx>,
}

impl UdpSocket {
    pub fn bind<A: ToSocketAddrs>(stack: NetworkStack, addr: A) -> io::Result<UdpSocket> {

    }

    pub fn send_to<A: ToSocketAddrs>(&mut self, buf: &[u8], addr: A) -> io::Result<usize> {
        if buf.len() > ::std::u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("Too large payload")));
        }
        let len = buf.len() as u16;
        match try!(util::first_socket_addr(addr)) {
            SocketAddr::V4(addr) => {
                let dst_ip = addr.ip();
                let dst_port = addr.port();
                if let Some(udp) = self.sender_cache.get_mut(&dst_ip) {
                    udp.send(len, |pkg| {
                        pkg.set_payload(buf);
                    });
                } else {

                }
                Ok(0)
            },
            SocketAddr::V6(addr) => {
                Err(io::Error::new(io::ErrorKind::InvalidInput, format!("Rips does not support IPv6 yet")))
            },
        }
    }
}
