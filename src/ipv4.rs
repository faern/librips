use std::net::Ipv4Addr;
use std::collections::HashMap;
use std::time::SystemTime;
use std::sync::{Arc, Mutex};

use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum};
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::{MutablePacket, Packet};

use {TxResult, RxResult, RxError};
use ethernet::EthernetListener;
use util::Buffer;

#[cfg(all(test, feature = "unit-tests"))]
use test::ethernet::EthernetTx;
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

pub type IpListenerLookup = HashMap<Ipv4Addr, HashMap<IpNextHeaderProtocol, Box<Ipv4Listener>>>;

// Header fields that are used to identify fragments as belonging to the same packet
type FragmentIdent = (Ipv4Addr, Ipv4Addr, u16);

/// Struct listening for ethernet frames containing IPv4 packets.
pub struct Ipv4Rx {
    listeners: Arc<Mutex<IpListenerLookup>>,
    buffers: HashMap<FragmentIdent, (Buffer, usize)>,
}

impl Ipv4Rx {
    pub fn new(listeners: Arc<Mutex<IpListenerLookup>>) -> Box<EthernetListener> {
        let this = Ipv4Rx {
            listeners: listeners,
            buffers: HashMap::new(),
        };
        Box::new(this) as Box<EthernetListener>
    }
}

impl Ipv4Rx {
    // Returns the Ipv4Packet contained in this EthernetPacket if it looks valid
    fn get_ipv4_pkg<'a>(eth_pkg: &'a EthernetPacket) -> Result<Ipv4Packet<'a>, RxError> {
        let eth_payload = eth_pkg.payload();
        if eth_payload.len() < Ipv4Packet::minimum_packet_size() {
            return Err(RxError::InvalidContent);
        }
        let total_length = {
            let ip_pkg = Ipv4Packet::new(eth_payload).unwrap();
            ip_pkg.get_total_length() as usize
        };
        if total_length > eth_payload.len() || total_length < Ipv4Packet::minimum_packet_size() {
            Err(RxError::InvalidContent)
        } else {
            Ok(Ipv4Packet::new(&eth_payload[..total_length]).unwrap())
        }
    }

    fn is_fragment(ip_pkg: &Ipv4Packet) -> bool {
        let mf = (ip_pkg.get_flags() & MORE_FRAGMENTS) != 0;
        let offset = ip_pkg.get_fragment_offset() != 0;
        mf || offset
    }

    // Saves a packet fragment to a buffer for reassembly. If the Ipv4Packet becomes complete
    // with the addition of `ip_pkg` then the complete reassembled packet is returned in a Buffer.
    fn save_fragment(&mut self, ip_pkg: Ipv4Packet) -> Result<Option<Buffer>, RxError> {
        let ident = Self::get_fragment_identification(&ip_pkg);
        if !self.buffers.contains_key(&ident) {
            if ip_pkg.get_fragment_offset() == 0 {
                let mut buffer = Buffer::new(::std::u16::MAX as usize);
                buffer.push(0, ip_pkg.packet()).unwrap();
                self.buffers.insert(ident, (buffer, 0));
                Ok(None)
            } else {
                Err(RxError::InvalidContent)
            }
        } else {
            let pkg_done = {
                let &mut (ref mut buffer, ref mut total_length) = self.buffers.get_mut(&ident).unwrap();
                let offset = Ipv4Packet::minimum_packet_size() + ip_pkg.get_fragment_offset() as usize * 8;
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
                    },
                }
            };
            if pkg_done {
                let (mut buffer, len) = self.buffers.remove(&ident).unwrap();
                {
                    let mut ip_pkg = MutableIpv4Packet::new(&mut buffer).unwrap();
                    ip_pkg.set_flags(NO_FLAGS);
                    ip_pkg.set_total_length(len as u16);
                }
                Ok(Some(buffer))
            } else {
                Ok(None)
            }
        }
    }

    fn get_fragment_identification(ip_pkg: &Ipv4Packet) -> FragmentIdent {
        let src = ip_pkg.get_source();
        let dst = ip_pkg.get_destination();
        let ident = ip_pkg.get_identification();
        (src, dst, ident)
    }

    // Forwards a complete packet its listener
    fn forward(&self, time: SystemTime, ip_pkg: Ipv4Packet) -> RxResult {
        let dest_ip = ip_pkg.get_destination();
        let next_level_protocol = ip_pkg.get_next_level_protocol();
        println!("Ipv4 got a packet to {}!", dest_ip);
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
            if let Some(buffer) = try!(self.save_fragment(ip_pkg)) {
                let reassembled_pkg = Ipv4Packet::new(&buffer).unwrap();
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

pub struct Ipv4Tx {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    ethernet: EthernetTx,
    next_identification: u16,
}

impl Ipv4Tx {
    pub fn new(ethernet: EthernetTx, src: Ipv4Addr, dst: Ipv4Addr) -> Ipv4Tx {
        Ipv4Tx {
            src: src,
            dst: dst,
            ethernet: ethernet,
            next_identification: 0,
        }
    }

    /// Sends an IPv4 packet to the network. If the given `dst_ip` is within
    /// the local network it will be sent directly to the MAC of that IP (taken
    /// from arp), otherwise it will be sent to the MAC of the configured
    /// gateway.
    pub fn send<T>(&mut self,
                   payload_size: u16,
                   next_level_protocol: IpNextHeaderProtocol,
                   builder: T)
                   -> TxResult
        where T: FnMut(&mut [u8])
    {
        let bytes_per_frame = self.ethernet.get_mtu() - Ipv4Packet::minimum_packet_size();
        if payload_size as usize <= bytes_per_frame {
            self.send_non_fragmented(payload_size, next_level_protocol, builder)
        } else {
            self.send_fragmented(payload_size, next_level_protocol, builder)
        }
    }

    fn send_non_fragmented<T>(&mut self,
                              payload_size: u16,
                              next_level_protocol: IpNextHeaderProtocol,
                              mut builder: T)
                              -> TxResult
        where T: FnMut(&mut [u8])
    {
        let total_size = Ipv4Packet::minimum_packet_size() as u16 + payload_size;
        let (src, dst) = (self.src, self.dst);
        let mut builder_wrapper = |payload: &mut [u8]| {
            let mut ip_pkg = MutableIpv4Packet::new(payload).unwrap();
            ip_pkg.set_header_length(5); // 5 is for no option fields
            ip_pkg.set_total_length(total_size);
            ip_pkg.set_identification(0);
            ip_pkg.set_flags(NO_FLAGS); // Allow routers to fragment it
            ip_pkg.set_fragment_offset(0);
            ip_pkg.set_source(src);
            ip_pkg.set_destination(dst);

            builder(ip_pkg.payload_mut());

            Self::set_ipv4_header(&mut ip_pkg, next_level_protocol);
        };
        self.ethernet.send(1,
                           total_size as usize,
                           EtherTypes::Ipv4,
                           &mut builder_wrapper)
    }

    fn send_fragmented<T>(&mut self,
                          payload_size: u16,
                          next_level_protocol: IpNextHeaderProtocol,
                          mut builder: T)
                          -> TxResult
        where T: FnMut(&mut [u8])
    {
        let payload_size = payload_size as usize;
        let mtu = self.ethernet.get_mtu();
        let bytes_per_frame = {
            let a = mtu - Ipv4Packet::minimum_packet_size();
            a - (a % 8) // Offset must be dividable by 8
        };

        let num_fragments = 1 + ((payload_size - 1) / bytes_per_frame);
        let mut payload = vec![0; payload_size];
        builder(&mut payload);

        let mut offset = 0;
        let mut chunks = payload.chunks(bytes_per_frame);
        let mut next_chunk = chunks.next();

        let (src, dst) = (self.src, self.dst);
        let identification = self.next_identification;
        self.next_identification.wrapping_add(1);

        let mut builder_wrapper = |payload: &mut [u8]| {
            let current_chunk = next_chunk.unwrap();
            next_chunk = chunks.next();
            let is_last_chunk = next_chunk.is_none();
            let total_size = Ipv4Packet::minimum_packet_size() + current_chunk.len();

            let mut ip_pkg = MutableIpv4Packet::new(payload).unwrap();
            ip_pkg.set_header_length(5); // 5 is for no option fields
            ip_pkg.set_total_length(total_size as u16);
            ip_pkg.set_identification(identification);
            ip_pkg.set_flags(if is_last_chunk {
                NO_FLAGS // More fragments not set
            } else {
                MORE_FRAGMENTS // More fragments set
            });
            ip_pkg.set_fragment_offset(offset / 8);
            ip_pkg.set_source(src);
            ip_pkg.set_destination(dst);

            ip_pkg.payload_mut()[..current_chunk.len()].copy_from_slice(current_chunk);

            Self::set_ipv4_header(&mut ip_pkg, next_level_protocol);

            offset += current_chunk.len() as u16;
        };
        self.ethernet.send(num_fragments, mtu, EtherTypes::Ipv4, &mut builder_wrapper)
    }

    fn set_ipv4_header(ip_pkg: &mut MutableIpv4Packet, next_level_protocol: IpNextHeaderProtocol) {
        ip_pkg.set_version(4);
        ip_pkg.set_dscp(0); // https://en.wikipedia.org/wiki/Differentiated_services
        ip_pkg.set_ecn(0); // https://en.wikipedia.org/wiki/Explicit_Congestion_Notification
        ip_pkg.set_next_level_protocol(next_level_protocol);
        ip_pkg.set_ttl(40);
        // ip_pkg.set_options(vec![]); // We currently don't support options

        ip_pkg.set_checksum(0);
        let checksum = checksum(&ip_pkg.to_immutable());
        ip_pkg.set_checksum(checksum);
    }
}


#[cfg(all(test, feature = "unit-tests"))]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex, mpsc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::SystemTime;
    use std::collections::HashMap;

    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
    use pnet::packet::ethernet::MutableEthernetPacket;
    use pnet::packet::{Packet, MutablePacket};

    use super::*;
    use {RxResult, RxError};
    use test::{ethernet, ipv4};
    use ethernet::EthernetListener;

    #[test]
    fn tx_fragmented() {
        let src = Ipv4Addr::new(192, 168, 10, 2);
        let dst = Ipv4Addr::new(192, 168, 10, 240);

        let (eth_tx, rx) = ethernet::EthernetTx::new();
        let mtu = eth_tx.get_mtu();
        let mut ipv4_tx = Ipv4Tx::new(eth_tx, src, dst);

        let max_payload_len = mtu - Ipv4Packet::minimum_packet_size();
        let pkg_size = max_payload_len + 5;
        let builder_call_count = AtomicUsize::new(0);
        let mut builder = |pkg: &mut [u8]| {
            assert_eq!(pkg.len(), pkg_size);
            let frame_split_i = mtu - Ipv4Packet::minimum_packet_size();
            pkg[0] = 12;
            pkg[frame_split_i - 1] = 13;
            pkg[frame_split_i] = 14;
            pkg[pkg_size - 1] = 15;
            builder_call_count.fetch_add(1, Ordering::SeqCst);
        };
        assert!(ipv4_tx.send(pkg_size as u16, IpNextHeaderProtocols::Tcp, &mut builder).is_ok());
        assert_eq!(builder_call_count.load(Ordering::SeqCst), 1);

        let frame1 = rx.try_recv().expect("Expected a frame to have been sent");
        let frame2 = rx.try_recv().expect("Expected a second frame to have been sent");
        assert!(rx.try_recv().is_err());
        let id1 = check_pkg(&frame1, src, dst, max_payload_len, true, 0, 12, 13);
        let id2 = check_pkg(&frame2, src, dst, 5, false, max_payload_len as u16, 14, 15);
        assert_eq!(id1, id2);
    }

    #[test]
    fn tx_not_fragmented() {
        let src = Ipv4Addr::new(192, 168, 10, 2);
        let dst = Ipv4Addr::new(192, 168, 10, 240);

        let (eth_tx, rx) = ethernet::EthernetTx::new();
        let mtu = eth_tx.get_mtu();
        let mut ipv4_tx = Ipv4Tx::new(eth_tx, src, dst);

        let pkg_payload_len = mtu - Ipv4Packet::minimum_packet_size();
        let pkg_size = pkg_payload_len - 5;
        let builder_call_count = AtomicUsize::new(0);
        let mut builder = |pkg: &mut [u8]| {
            assert_eq!(pkg.len(), pkg_size);
            pkg[0] = 100;
            pkg[pkg_size - 1] = 99;
            builder_call_count.fetch_add(1, Ordering::SeqCst);
        };
        assert!(ipv4_tx.send(pkg_size as u16, IpNextHeaderProtocols::Tcp, &mut builder).is_ok());
        assert_eq!(builder_call_count.load(Ordering::SeqCst), 1);

        let frame = rx.try_recv().expect("Expected a frame to have been sent");
        assert!(rx.try_recv().is_err());
        check_pkg(&frame, src, dst, pkg_size, false, 0, 100, 99);
    }

    #[test]
    fn rx_non_fragmented() {
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
        // Send first part of a fragmented packet and make sure nothing is sent to the listener
        {
            let mut ip_pkg = MutableIpv4Packet::new(pkg.payload_mut()).unwrap();
            ip_pkg.set_destination(dst);
            ip_pkg.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ip_pkg.set_flags(MORE_FRAGMENTS);
            ip_pkg.set_fragment_offset(0);
            ip_pkg.set_identification(137);
            ip_pkg.set_header_length(5); // No options
            ip_pkg.set_total_length(20 + 16);
        }

        ipv4_rx.recv(SystemTime::now(), &pkg.to_immutable()).unwrap();
        assert!(rx.try_recv().is_err());

        // Send a packet with different identification number and make sure it doesn't merge
        {
            let mut ip_pkg = MutableIpv4Packet::new(pkg.payload_mut()).unwrap();
            ip_pkg.set_flags(NO_FLAGS);
            ip_pkg.set_fragment_offset(16 / 8);
            ip_pkg.set_identification(299);
            ip_pkg.set_total_length(20 + 8);
        }
        assert_eq!(ipv4_rx.recv(SystemTime::now(), &pkg.to_immutable()), Err(RxError::InvalidContent));
        assert!(rx.try_recv().is_err());

        // Send final part of fragmented packet
        {
            let mut ip_pkg = MutableIpv4Packet::new(pkg.payload_mut()).unwrap();
            ip_pkg.set_identification(137);
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
        let arp_listener = Box::new(ipv4::MockIpv4Listener{ tx: tx }) as Box<Ipv4Listener>;

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
        assert_eq!(ip_pkg.get_destination(), dst);
        let actual_payload_len = ip_pkg.get_total_length() as usize -
                                 Ipv4Packet::minimum_packet_size();
        assert_eq!(actual_payload_len, payload_len);
        assert_eq!(ip_pkg.get_flags() == MORE_FRAGMENTS, is_fragment);
        assert_eq!(ip_pkg.get_fragment_offset() * 8, offset);
        let payload = ip_pkg.payload();
        assert_eq!(payload[0], first);
        assert_eq!(payload[payload_len - 1], last);
        ip_pkg.get_identification()
    }
}
