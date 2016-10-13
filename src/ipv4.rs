use std::net::Ipv4Addr;
use std::collections::HashMap;
use std::time::SystemTime;
use std::sync::{Arc, Mutex};
use std::cmp;

use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum};
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::{MutablePacket, Packet};

use {Protocol, RxError, RxResult, TxResult};
use ethernet::{EthernetListener, EthernetProtocol};
use util::Buffer;

#[cfg(all(test, feature = "unit-tests"))]
use testing::ethernet::EthernetTx;
#[cfg(not(all(test, feature = "unit-tests")))]
use ethernet::EthernetTx;

pub const MORE_FRAGMENTS: u8 = 0b001;
pub const DONT_FRAGMENT: u8 = 0b010;
pub const NO_FLAGS: u8 = 0b000;

/// Anyone interested in receiving IPv4 packets from `Ipv4` must implement this.
pub trait Ipv4Listener: Send {
    /// Called by the library to deliver an `Ipv4Packet` to a listener.
    fn recv(&mut self, time: SystemTime, packet: Ipv4Packet) -> RxResult;
}

/// Type binding for how the listeners in `Ipv4Rx` are structured.
pub type IpListenerLookup = HashMap<Ipv4Addr, HashMap<IpNextHeaderProtocol, Box<Ipv4Listener>>>;

// Header fields that are used to identify fragments as belonging to the same
// packet
type FragmentIdent = (Ipv4Addr, Ipv4Addr, u16);

/// Listener and parser for IPv4 packets. Receives ethernet frames from the
/// `EthernetRx` it's owned by and forwards them to the correct `Ipv4Listener`.
/// Will cache and reassemble fragmented packets before forwarding them.
pub struct Ipv4Rx {
    listeners: Arc<Mutex<IpListenerLookup>>,
    buffers: HashMap<FragmentIdent, (Buffer, usize)>,
}

impl Ipv4Rx {
    /// Creates a new `Ipv4Rx` with the given listeners. Listeners can't be
    /// changed later. Returns the instance casted for easy addition to
    /// the `EthernetRx` listener `Vec`.
    pub fn new(listeners: Arc<Mutex<IpListenerLookup>>) -> Box<EthernetListener> {
        let this = Ipv4Rx {
            listeners: listeners,
            buffers: HashMap::new(),
        };
        Box::new(this) as Box<EthernetListener>
    }
}

impl Ipv4Rx {
    /// Returns the Ipv4Packet contained in this EthernetPacket if it looks
    /// valid
    fn get_ipv4_pkg<'a>(eth_pkg: &'a EthernetPacket) -> Result<Ipv4Packet<'a>, RxError> {
        let eth_payload = eth_pkg.payload();
        if eth_payload.len() < Ipv4Packet::minimum_packet_size() {
            return Err(RxError::InvalidLength);
        }
        let total_length = {
            let ip_pkg = Ipv4Packet::new(eth_payload).unwrap();
            ip_pkg.get_total_length() as usize
        };
        if total_length > eth_payload.len() || total_length < Ipv4Packet::minimum_packet_size() {
            Err(RxError::InvalidLength)
        } else {
            let ip_pkg = Ipv4Packet::new(&eth_payload[..total_length]).unwrap();
            if ip_pkg.get_checksum() != checksum(&ip_pkg) {
                Err(RxError::InvalidChecksum)
            } else {
                Ok(ip_pkg)
            }
        }
    }

    fn is_fragment(ip_pkg: &Ipv4Packet) -> bool {
        let mf = (ip_pkg.get_flags() & MORE_FRAGMENTS) != 0;
        let offset = ip_pkg.get_fragment_offset() != 0;
        mf || offset
    }

    /// Saves a packet fragment to a buffer for reassembly. If the Ipv4Packet
    /// becomes complete with the addition of `ip_pkg` then the complete
    /// reassembled packet is returned in a Buffer.
    fn save_fragment(&mut self,
                     ip_pkg: Ipv4Packet)
                     -> Result<Option<Ipv4Packet<'static>>, RxError> {
        let ident = Self::get_fragment_identification(&ip_pkg);
        if !self.buffers.contains_key(&ident) {
            try!(self.start_new_fragment(ip_pkg, ident));
            Ok(None)
        } else {
            let pkg_done = {
                let &mut (ref mut buffer, ref mut total_length) =
                    self.buffers.get_mut(&ident).unwrap();
                let offset = Ipv4Packet::minimum_packet_size() +
                             ip_pkg.get_fragment_offset() as usize * 8;
                // Check if this is the last fragment
                if (ip_pkg.get_flags() & MORE_FRAGMENTS) == 0 {
                    if *total_length != 0 {
                        return Err(RxError::InvalidContent);
                    } else {
                        *total_length = offset + ip_pkg.payload().len();
                    }
                }
                match buffer.push(offset, ip_pkg.payload()) {
                    Ok(i) => i == *total_length,
                    Err(_) => {
                        return Err(RxError::InvalidContent);
                    }
                }
            };
            if pkg_done {
                let (buffer, len) = self.buffers.remove(&ident).unwrap();
                let mut ip_pkg = MutableIpv4Packet::owned(buffer.into_boxed_slice()).unwrap();
                ip_pkg.set_flags(NO_FLAGS);
                ip_pkg.set_total_length(len as u16);
                let csum = checksum(&ip_pkg.to_immutable());
                ip_pkg.set_checksum(csum);
                Ok(Some(ip_pkg.consume_to_immutable()))
            } else {
                Ok(None)
            }
        }
    }

    fn start_new_fragment(&mut self, ip_pkg: Ipv4Packet, ident: FragmentIdent) -> RxResult {
        if ip_pkg.get_fragment_offset() == 0 {
            let mut buffer = Buffer::new(::std::u16::MAX as usize);
            buffer.push(0, ip_pkg.packet()).unwrap();
            self.buffers.insert(ident, (buffer, 0));
            Ok(())
        } else {
            Err(RxError::InvalidContent)
        }
    }

    fn get_fragment_identification(ip_pkg: &Ipv4Packet) -> FragmentIdent {
        let src = ip_pkg.get_source();
        let dst = ip_pkg.get_destination();
        let ident = ip_pkg.get_identification();
        (src, dst, ident)
    }

    /// Forwards a complete packet to its listener
    fn forward(&self, time: SystemTime, ip_pkg: Ipv4Packet) -> RxResult {
        let dest_ip = ip_pkg.get_destination();
        let next_level_protocol = ip_pkg.get_next_level_protocol();
        trace!("Ipv4 got a packet to {}!", dest_ip);
        let mut listeners = try!(self.listeners.lock().or(Err(RxError::PoisonedLock)));
        if let Some(mut listeners) = listeners.get_mut(&dest_ip) {
            if let Some(mut listener) = listeners.get_mut(&next_level_protocol) {
                listener.recv(time, ip_pkg)
            } else {
                Err(RxError::NoListener(format!("Ipv4 {:?}", next_level_protocol)))
            }
        } else {
            Err(RxError::NoListener(format!("Ipv4 {}", dest_ip)))
        }
    }
}

impl EthernetListener for Ipv4Rx {
    fn recv(&mut self, time: SystemTime, eth_pkg: &EthernetPacket) -> RxResult {
        let ip_pkg = try!(Self::get_ipv4_pkg(eth_pkg));
        if Self::is_fragment(&ip_pkg) {
            if let Some(reassembled_pkg) = try!(self.save_fragment(ip_pkg)) {
                self.forward(time, reassembled_pkg)
            } else {
                Ok(())
            }
        } else {
            self.forward(time, ip_pkg)
        }
    }

    fn get_ethertype(&self) -> EtherType {
        EtherTypes::Ipv4
    }
}

/// IPv4 packet builder and sender. Will fragment packets larger than the
/// MTU reported by the underlying `EthernetTx` given to the constructor.
pub struct Ipv4Tx {
    /// The source IP of packets built by this instance.
    pub src: Ipv4Addr,

    /// The destination IP of the packets built by this instance.
    pub dst: Ipv4Addr,

    mtu: usize,

    ethernet: EthernetTx,
    next_identification: u16,
}

impl Ipv4Tx {
    /// Constructs a new `Ipv4Tx`.
    pub fn new(ethernet: EthernetTx, src: Ipv4Addr, dst: Ipv4Addr, mtu: usize) -> Ipv4Tx {
        assert!(mtu >= Ipv4Packet::minimum_packet_size());
        Ipv4Tx {
            src: src,
            dst: dst,
            mtu: mtu,
            ethernet: ethernet,
            next_identification: 0,
        }
    }

    /// Sends an IPv4 packet to the network. If the given `dst_ip` is within
    /// the local network it will be sent directly to the MAC of that IP (taken
    /// from arp), otherwise it will be sent to the MAC of the configured
    /// gateway.
    pub fn send<P: Ipv4Protocol>(&mut self, payload: P) -> TxResult {
        let payload_len = payload.len();
        let builder = Ipv4Builder::new(self.src, self.dst, self.next_identification, payload);
        self.next_identification.wrapping_add(1);

        let max_payload_per_fragment = self.max_payload_per_fragment();
        if payload_len as usize <= max_payload_per_fragment {
            let size = payload_len as usize + Ipv4Packet::minimum_packet_size();
            self.ethernet.send(1, size, builder)
        } else {
            let fragments = 1 + ((payload_len as usize - 1) / max_payload_per_fragment);
            let size = max_payload_per_fragment + Ipv4Packet::minimum_packet_size();
            self.ethernet.send(fragments, size, builder)
        }
    }

    pub fn max_payload_per_fragment(&self) -> usize {
        (self.mtu - Ipv4Packet::minimum_packet_size()) & !0b111
    }
}

pub trait Ipv4Protocol: Protocol {
    fn next_level_protocol(&self) -> IpNextHeaderProtocol;
}

pub struct BasicIpv4Protocol {
    next_level_protocol: IpNextHeaderProtocol,
    offset: usize,
    payload: Vec<u8>,
}

impl BasicIpv4Protocol {
    pub fn new(next_level_protocol: IpNextHeaderProtocol, payload: Vec<u8>) -> Self {
        assert!(payload.len() <= ::std::u16::MAX as usize);
        BasicIpv4Protocol {
            next_level_protocol: next_level_protocol,
            offset: 0,
            payload: payload,
        }
    }
}

impl Ipv4Protocol for BasicIpv4Protocol {
    fn next_level_protocol(&self) -> IpNextHeaderProtocol {
        self.next_level_protocol
    }
}

impl Protocol for BasicIpv4Protocol {
    fn len(&self) -> usize {
        self.payload.len()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        let start = self.offset;
        let end = cmp::min(start + buffer.len(), self.payload.len());
        self.offset = end;
        buffer.copy_from_slice(&self.payload[start..end]);
    }
}

pub struct Ipv4Builder<P: Ipv4Protocol> {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    offset: usize,
    identification: u16,
    payload: P,
}

impl<P: Ipv4Protocol> Ipv4Builder<P> {
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, identification: u16, payload: P) -> Self {
        Ipv4Builder {
            src: src,
            dst: dst,
            offset: 0,
            identification: identification,
            payload: payload,
        }
    }
}

impl<P: Ipv4Protocol> EthernetProtocol for Ipv4Builder<P> {
    fn ether_type(&self) -> EtherType {
        EtherTypes::Ipv4
    }
}

impl<P: Ipv4Protocol> Protocol for Ipv4Builder<P> {
    fn len(&self) -> usize {
        Ipv4Packet::minimum_packet_size() + self.payload.len()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        assert!(buffer.len() <= ::std::u16::MAX as usize);
        let mut pkg = MutableIpv4Packet::new(buffer).unwrap();
        pkg.set_version(4);
        pkg.set_dscp(0); // https://en.wikipedia.org/wiki/Differentiated_services
        pkg.set_ecn(0); // https://en.wikipedia.org/wiki/Explicit_Congestion_Notification
        pkg.set_ttl(40);
        // ip_pkg.set_options(vec![]); // We currently don't support options
        pkg.set_header_length(5); // 5 is for no option fields
        pkg.set_identification(self.identification);
        pkg.set_source(self.src);
        pkg.set_destination(self.dst);
        pkg.set_fragment_offset((self.offset / 8) as u16);

        let bytes_remaining = self.payload.len() - self.offset;
        let bytes_max = pkg.payload().len();
        let payload_size = if bytes_remaining <= bytes_max {
            pkg.set_flags(NO_FLAGS);
            bytes_remaining
        } else {
            pkg.set_flags(MORE_FRAGMENTS);
            bytes_max & !0b111 // Round down to divisable by 8
        };
        let total_length = payload_size + Ipv4Packet::minimum_packet_size();
        pkg.set_total_length(total_length as u16);

        pkg.set_next_level_protocol(self.payload.next_level_protocol());
        self.payload.build(&mut pkg.payload_mut()[..payload_size]);

        let checksum = checksum(&pkg.to_immutable());
        pkg.set_checksum(checksum);

        self.offset += payload_size;
    }
}

#[cfg(all(test, feature = "unit-tests"))]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex, mpsc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::SystemTime;
    use std::collections::HashMap;

    use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
    use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum};
    use pnet::packet::ethernet::MutableEthernetPacket;
    use pnet::packet::{MutablePacket, Packet};

    use super::*;
    use {RxError, RxResult};
    use testing::{ethernet, ipv4};
    use testing::ipv4::TestIpv4Protocol;
    use ethernet::EthernetListener;

    #[test]
    fn tx_fragmented() {
        let src = Ipv4Addr::new(192, 168, 10, 2);
        let dst = Ipv4Addr::new(192, 168, 10, 240);

        let (eth_tx, rx) = ethernet::EthernetTx::new();
        let mut ipv4_tx = Ipv4Tx::new(eth_tx, src, dst, 1500);

        let max_payload_len = ipv4_tx.max_payload_per_fragment();
        let pkg_size = max_payload_len + 5;

        let call_count = AtomicUsize::new(0);
        let call_bytes = AtomicUsize::new(0);
        let mut builder = TestIpv4Protocol::new_counted(pkg_size, &call_count, &call_bytes);
        assert!(ipv4_tx.send(builder).is_ok());
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
        assert_eq!(call_bytes.load(Ordering::SeqCst), pkg_size);

        let frame1 = rx.try_recv().expect("Expected a frame to have been sent");
        let frame2 = rx.try_recv().expect("Expected a second frame to have been sent");
        assert!(rx.try_recv().is_err());
        let id1 = check_pkg(&frame1, src, dst, max_payload_len, true, 0, 100, 99);
        let id2 = check_pkg(&frame2, src, dst, 5, false, max_payload_len as u16, 100, 99);
        assert_eq!(id1, id2);
    }

    #[test]
    fn tx_not_fragmented() {
        let src = Ipv4Addr::new(192, 168, 10, 2);
        let dst = Ipv4Addr::new(192, 168, 10, 240);

        let (eth_tx, rx) = ethernet::EthernetTx::new();
        let mut ipv4_tx = Ipv4Tx::new(eth_tx, src, dst, 1500);

        let max_payload_len = ipv4_tx.max_payload_per_fragment();
        let pkg_size = max_payload_len - 5;

        let call_count = AtomicUsize::new(0);
        let call_bytes = AtomicUsize::new(0);
        let mut builder = TestIpv4Protocol::new_counted(pkg_size, &call_count, &call_bytes);
        assert!(ipv4_tx.send(builder).is_ok());
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
        assert_eq!(call_bytes.load(Ordering::SeqCst), pkg_size);

        let frame = rx.try_recv().expect("Expected a frame to have been sent");
        assert!(rx.try_recv().is_err());
        check_pkg(&frame, src, dst, pkg_size, false, 0, 100, 99);
    }

    #[test]
    fn rx_not_fragmented() {
        let dst = Ipv4Addr::new(127, 0, 0, 1);
        let (mut ipv4_rx, rx) = setup_rx(dst);

        let mut buffer = vec![0; 100];
        let mut pkg = MutableEthernetPacket::new(&mut buffer).unwrap();
        {
            let mut ip_pkg = MutableIpv4Packet::new(pkg.payload_mut()).unwrap();
            ip_pkg.set_destination(dst);
            ip_pkg.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ip_pkg.set_flags(DONT_FRAGMENT);
            ip_pkg.set_header_length(5); // No options
            ip_pkg.set_total_length(20 + 15);
            let csum = checksum(&ip_pkg.to_immutable());
            ip_pkg.set_checksum(csum);
        }

        ipv4_rx.recv(SystemTime::now(), &pkg.to_immutable()).unwrap();
        let rx_pkg = rx.try_recv().expect("Expected a packet to have been delivered");
        let rx_ip_pkg = Ipv4Packet::new(&rx_pkg[..]).unwrap();
        assert_eq!(rx_ip_pkg.get_destination(), dst);
        assert_eq!(rx_ip_pkg.get_flags(), DONT_FRAGMENT);
        assert_eq!(rx_ip_pkg.get_total_length(), 35);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn rx_fragmented() {
        let dst = Ipv4Addr::new(127, 0, 0, 1);
        let (mut ipv4_rx, rx) = setup_rx(dst);

        let mut buffer = vec![0; 100];
        let mut pkg = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        // Send first part of a fragmented packet and make sure nothing is sent to the
        // listener
        {
            let mut ip_pkg = MutableIpv4Packet::new(pkg.payload_mut()).unwrap();
            ip_pkg.set_destination(dst);
            ip_pkg.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ip_pkg.set_flags(MORE_FRAGMENTS);
            ip_pkg.set_fragment_offset(0);
            ip_pkg.set_identification(137);
            ip_pkg.set_header_length(5); // No options
            ip_pkg.set_total_length(20 + 16);
            let csum = checksum(&ip_pkg.to_immutable());
            ip_pkg.set_checksum(csum);
        }

        ipv4_rx.recv(SystemTime::now(), &pkg.to_immutable()).unwrap();
        assert!(rx.try_recv().is_err());

        // Send a packet with different identification number and make sure it doesn't
        // merge
        {
            let mut ip_pkg = MutableIpv4Packet::new(pkg.payload_mut()).unwrap();
            ip_pkg.set_flags(NO_FLAGS);
            ip_pkg.set_fragment_offset(16 / 8);
            ip_pkg.set_identification(299);
            ip_pkg.set_total_length(20 + 8);
            let csum = checksum(&ip_pkg.to_immutable());
            ip_pkg.set_checksum(csum);
        }
        assert_eq!(ipv4_rx.recv(SystemTime::now(), &pkg.to_immutable()),
                   Err(RxError::InvalidContent));
        assert!(rx.try_recv().is_err());

        // Send final part of fragmented packet
        {
            let mut ip_pkg = MutableIpv4Packet::new(pkg.payload_mut()).unwrap();
            ip_pkg.set_identification(137);
            let csum = checksum(&ip_pkg.to_immutable());
            ip_pkg.set_checksum(csum);
        }
        ipv4_rx.recv(SystemTime::now(), &pkg.to_immutable()).unwrap();
        let rx_pkg = rx.try_recv().expect("Expected a packet to have been delivered");
        let rx_ip_pkg = Ipv4Packet::new(&rx_pkg[..]).unwrap();
        assert_eq!(rx_ip_pkg.get_destination(), dst);
        assert_eq!(rx_ip_pkg.get_flags(), NO_FLAGS);
        assert_eq!(rx_ip_pkg.get_total_length(), 20 + 16 + 8);
        assert!(rx.try_recv().is_err());
    }

    fn setup_rx(dst: Ipv4Addr) -> (Box<EthernetListener>, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel();
        let arp_listener = Box::new(ipv4::MockIpv4Listener { tx: tx }) as Box<Ipv4Listener>;

        let mut ip_listeners = HashMap::new();
        ip_listeners.insert(IpNextHeaderProtocols::Icmp, arp_listener);

        let mut listeners = HashMap::new();
        listeners.insert(dst, ip_listeners);

        let listeners = Arc::new(Mutex::new(listeners));
        let mut ipv4_rx = Ipv4Rx::new(listeners);
        (ipv4_rx, rx)
    }

    fn check_pkg(payload: &[u8],
                 src: Ipv4Addr,
                 dst: Ipv4Addr,
                 payload_len: usize,
                 is_fragment: bool,
                 offset: u16,
                 first: u8,
                 last: u8)
                 -> u16 {
        let ip_pkg = Ipv4Packet::new(payload).unwrap();
        assert_eq!(ip_pkg.get_source(), src);
        assert_eq!(ip_pkg.get_destination(), dst);;
        assert_eq!(ip_pkg.get_total_length() as usize,
                   payload_len + Ipv4Packet::minimum_packet_size());
        assert_eq!(ip_pkg.get_flags() == MORE_FRAGMENTS, is_fragment);
        assert_eq!(ip_pkg.get_fragment_offset() * 8, offset);
        let payload = ip_pkg.payload();
        assert_eq!(payload[0], first);
        assert_eq!(payload[payload_len - 1], last);
        ip_pkg.get_identification()
    }
}
