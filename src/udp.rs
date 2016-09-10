use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::io;
use std::sync::{Arc, Mutex, mpsc};
use std::collections::HashMap;
use std::time::SystemTime;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::udp::{MutableUdpPacket, UdpPacket, ipv4_checksum};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

use {RxError, RxResult, TxError, TxResult};
#[cfg(not(feature = "unit-tests"))]
use {NetworkStack, StackError, StackResult};

use ipv4::{Ipv4Listener, Ipv4Tx};
use util;

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
}

impl UdpRx {
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

pub struct UdpTx {
    src: u16,
    dst: u16,
    ipv4: Ipv4Tx,
}

impl UdpTx {
    pub fn new(ipv4: Ipv4Tx, src: u16, dst: u16) -> UdpTx {
        UdpTx {
            src: src,
            dst: dst,
            ipv4: ipv4,
        }
    }

    pub fn send<T>(&mut self, payload_size: u16, mut builder: T) -> TxResult
        where T: FnMut(&mut MutableUdpPacket)
    {
        let total_size = UdpPacket::minimum_packet_size() as u16 + payload_size;
        let (src, dst) = (self.src, self.dst);
        let src_ip = self.ipv4.src;
        let dst_ip = self.ipv4.dst;
        let mut builder_wrapper = |pkg: &mut [u8]| {
            let mut udp_pkg = MutableUdpPacket::new(pkg).unwrap();
            udp_pkg.set_source(src);
            udp_pkg.set_destination(dst);
            udp_pkg.set_length(total_size);
            builder(&mut udp_pkg);

            udp_pkg.set_checksum(0);
            let checksum = ipv4_checksum(&udp_pkg.to_immutable(),
                                         src_ip,
                                         dst_ip,
                                         IpNextHeaderProtocols::Udp);
            udp_pkg.set_checksum(checksum);
        };
        self.ipv4.send(total_size, IpNextHeaderProtocols::Udp, &mut builder_wrapper)
    }
}

#[derive(Clone)]
struct UdpSocketListener {
    chan: mpsc::Sender<(SystemTime, Box<[u8]>)>,
}

impl UdpListener for UdpSocketListener {
    fn recv(&mut self, time: SystemTime, packet: &Ipv4Packet) -> (RxResult, bool) {
        let data = packet.packet().to_vec().into_boxed_slice();
        let resume = self.chan.send((time, data)).is_ok();
        (Ok(()), resume)
    }
}

struct UdpSocketReader {
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

#[cfg(not(feature = "unit-tests"))]
pub struct UdpSocket {
    socket_addr: SocketAddr,
    stack: Arc<Mutex<NetworkStack>>,
    tx_cache: HashMap<SocketAddrV4, UdpTx>,
    rx: Option<UdpSocketReader>,
}

#[cfg(not(feature = "unit-tests"))]
impl UdpSocket {
    pub fn bind<A: ToSocketAddrs>(stack: Arc<Mutex<NetworkStack>>,
                                  addr: A)
                                  -> io::Result<UdpSocket> {
        let mut socket_reader = UdpSocketReader::new();
        let socket_addr = {
            let mut stack = stack.lock().unwrap();
            try!(stack.udp_listen(addr, socket_reader.listener()))
        };
        Ok(UdpSocket {
            socket_addr: socket_addr,
            stack: stack,
            tx_cache: HashMap::new(),
            rx: Some(socket_reader),
        })
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.rx.as_ref().unwrap().recv_from(buf)
    }

    pub fn send_to<A: ToSocketAddrs>(&mut self, buf: &[u8], addr: A) -> io::Result<usize> {
        match try!(util::first_socket_addr(addr)) {
            SocketAddr::V4(dst) => {
                self.internal_send(buf, dst)
                    .map(|_| buf.len())
                    .map_err(|e| e.into())
            }
            SocketAddr::V6(_dst) => {
                Err(io::Error::new(io::ErrorKind::InvalidInput,
                                   "Rips does not support IPv6 yet".to_owned()))
            }
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.socket_addr)
    }

    pub fn try_clone(&self) -> io::Result<UdpSocket> {
        Ok(UdpSocket {
            socket_addr: self.socket_addr,
            stack: self.stack.clone(),
            tx_cache: HashMap::new(),
            rx: None,
        })
    }

    fn internal_send(&mut self, buf: &[u8], dst: SocketAddrV4) -> StackResult<()> {
        match self.internal_send_on_cached_tx(buf, dst) {
            Err(TxError::InvalidTx) => {
                let (dst_ip, dst_port) = (*dst.ip(), dst.port());
                let new_udp_tx = {
                    let mut stack = self.stack.lock().unwrap();
                    try!(stack.udp_tx(dst_ip, self.socket_addr.port(), dst_port))
                };
                self.tx_cache.insert(dst, new_udp_tx);
                self.internal_send(buf, dst)
            }
            result => result.map_err(StackError::TxError),
        }
    }

    fn internal_send_on_cached_tx(&mut self, buf: &[u8], dst: SocketAddrV4) -> TxResult {
        if buf.len() > ::std::u16::MAX as usize {
            return Err(TxError::TooLargePayload);
        }
        let len = buf.len() as u16;

        if let Some(udp_tx) = self.tx_cache.get_mut(&dst) {
            udp_tx.send(len, |pkg| {
                pkg.set_payload(buf);
            })
        } else {
            // No cached UdpTx is treated as an existing but outdated one
            Err(TxError::InvalidTx)
        }
    }
}
