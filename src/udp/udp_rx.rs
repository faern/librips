use {RxError, RxResult};
use ipv4::Ipv4Listener;

use pnet::packet::Packet;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex, mpsc};
use std::time::SystemTime;

pub trait UdpListener: Send {
    fn recv(&mut self, time: SystemTime, packet: &Ipv4Packet) -> (RxResult, bool);
}

pub type UdpListenerLookup = HashMap<u16, Box<UdpListener>>;

pub struct UdpRx {
    listeners: Arc<Mutex<UdpListenerLookup>>,
}

impl UdpRx {
    pub fn new(listeners: Arc<Mutex<UdpListenerLookup>>) -> UdpRx {
        UdpRx { listeners: listeners }
    }

    fn get_port(pkg: &Ipv4Packet) -> Result<u16, RxError> {
        let payload = pkg.payload();
        if payload.len() < UdpPacket::minimum_packet_size() {
            return Err(RxError::InvalidContent);
        }
        let (port, length) = {
            let udp_pkg = UdpPacket::new(payload).unwrap();
            (udp_pkg.get_destination(), udp_pkg.get_length() as usize)
        };
        if length > payload.len() || length < UdpPacket::minimum_packet_size() {
            Err(RxError::InvalidContent)
        } else {
            Ok(port)
        }
    }
}

impl Ipv4Listener for UdpRx {
    fn recv(&mut self, time: SystemTime, ip_pkg: Ipv4Packet) -> RxResult {
        let port = try!(Self::get_port(&ip_pkg));
        let mut listeners = self.listeners.lock().unwrap();
        if let Some(listener) = listeners.get_mut(&port) {
            let (result, _resume) = listener.recv(time, &ip_pkg);
            result
            // TODO: When resume turns false, remove this socket.
        } else {
            Err(RxError::NoListener(format!("Udp, no listener for port {:?}", port)))
        }
    }
}

#[derive(Clone)]
pub struct UdpSocketListener {
    chan: mpsc::Sender<(SystemTime, Box<[u8]>)>,
}

impl UdpListener for UdpSocketListener {
    fn recv(&mut self, time: SystemTime, packet: &Ipv4Packet) -> (RxResult, bool) {
        let data = packet.packet().to_vec().into_boxed_slice();
        let resume = self.chan.send((time, data)).is_ok();
        (Ok(()), resume)
    }
}

pub struct UdpSocketReader {
    port: mpsc::Receiver<(SystemTime, Box<[u8]>)>,
    chan: UdpSocketListener,
}

impl UdpSocketReader {
    pub fn new() -> UdpSocketReader {
        let (tx, rx) = mpsc::channel();
        UdpSocketReader {
            port: rx,
            chan: UdpSocketListener { chan: tx },
        }
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (_time, data) = self.port.recv().unwrap();
        let ipv4_pkg = Ipv4Packet::new(&data).unwrap();
        let ip = ipv4_pkg.get_source();
        let udp_pkg = UdpPacket::new(ipv4_pkg.payload()).unwrap();
        let port = udp_pkg.get_source();
        let data = udp_pkg.payload();
        if data.len() > buf.len() {
            Err(io::Error::new(io::ErrorKind::InvalidInput,
                               "Data does not fit buffer".to_owned()))
        } else {
            buf[..data.len()].copy_from_slice(data);
            Ok((data.len(), SocketAddr::V4(SocketAddrV4::new(ip, port))))
        }
    }

    pub fn listener(&mut self) -> UdpSocketListener {
        self.chan.clone()
    }
}
