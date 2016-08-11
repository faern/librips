use std::net::Ipv4Addr;
use std::collections::HashMap;
use std::convert::From;
use std::time::SystemTime;
use std::sync::{Arc, Mutex};

use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum};
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::{MutablePacket, Packet};

use ipnetwork;

use {TxResult, RxResult, RxError};
use ethernet::EthernetListener;

#[cfg(all(test, feature = "unit-tests"))]
use test::ethernet::EthernetTx;
#[cfg(not(all(test, feature = "unit-tests")))]
use ethernet::EthernetTx;

/// Represents an error in an `IpConf`.
#[derive(Debug)]
pub enum IpConfError {
    /// The given network configuration was not valid. For example invalid
    /// prefix.
    InvalidNetwork(ipnetwork::IpNetworkError),

    /// The gateway is not inside the local network.
    GwNotInNetwork,
}

impl From<ipnetwork::IpNetworkError> for IpConfError {
    fn from(e: ipnetwork::IpNetworkError) -> Self {
        IpConfError::InvalidNetwork(e)
    }
}

/// Anyone interested in receiving IPv4 packets from `Ipv4` must implement this.
pub trait Ipv4Listener: Send {
    /// Called by the library to deliver an `Ipv4Packet` to a listener.
    fn recv(&mut self, time: SystemTime, packet: Ipv4Packet) -> RxResult<()>;
}

pub type IpListenerLookup = HashMap<Ipv4Addr, HashMap<IpNextHeaderProtocol, Box<Ipv4Listener>>>;

/// Struct listening for ethernet frames containing IPv4 packets.
pub struct Ipv4Rx {
    listeners: Arc<Mutex<IpListenerLookup>>,
}

impl Ipv4Rx {
    pub fn new(listeners: Arc<Mutex<IpListenerLookup>>) -> Box<EthernetListener> {
        let this = Ipv4Rx { listeners: listeners };
        Box::new(this) as Box<EthernetListener>
    }
}

impl Ipv4Rx {
    fn get_ipv4_pkg<'a>(eth_pkg: &'a EthernetPacket) -> RxResult<Ipv4Packet<'a>> {
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
}

impl EthernetListener for Ipv4Rx {
    fn recv(&mut self, time: SystemTime, eth_pkg: &EthernetPacket) -> RxResult<()> {
        let ip_pkg = try!(Self::get_ipv4_pkg(eth_pkg));
        let dest_ip = ip_pkg.get_destination();
        let next_level_protocol = ip_pkg.get_next_level_protocol();
        println!("Ipv4 got a packet to {}!", dest_ip);
        let mut listeners = self.listeners.lock().unwrap();
        if let Some(mut listeners) = listeners.get_mut(&dest_ip) {
            if let Some(mut listener) = listeners.get_mut(&next_level_protocol) {
                listener.recv(time, ip_pkg)
            } else {
                Err(RxError::NoListener(format!("Ipv4, no one was listening to {:?}", next_level_protocol)))
            }
        } else {
            Err(RxError::NoListener(format!("Ipv4 is not listening to {} on this interface", dest_ip)))
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
}

impl Ipv4Tx {
    pub fn new(ethernet: EthernetTx, src: Ipv4Addr, dst: Ipv4Addr) -> Ipv4Tx {
        Ipv4Tx {
            src: src,
            dst: dst,
            ethernet: ethernet,
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
                   -> TxResult<()>
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
                              -> TxResult<()>
        where T: FnMut(&mut [u8])
    {
        let total_size = Ipv4Packet::minimum_packet_size() as u16 + payload_size;
        let (src, dst) = (self.src, self.dst);
        let mut builder_wrapper = |payload: &mut [u8]| {
            let mut ip_pkg = MutableIpv4Packet::new(payload).unwrap();
            ip_pkg.set_header_length(5); // 5 is for no option fields
            ip_pkg.set_total_length(total_size);
            ip_pkg.set_identification(0); // Use when implementing fragmentation
            ip_pkg.set_flags(0x000); // Allow routers to fragment it
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
                          -> TxResult<()>
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
        builder(&mut payload[..]);

        let mut offset = 0;
        let mut chunks = payload.chunks(bytes_per_frame);
        let mut next_chunk = chunks.next();

        let (src, dst) = (self.src, self.dst);

        let mut builder_wrapper = |payload: &mut [u8]| {
            let current_chunk = next_chunk.unwrap();
            next_chunk = chunks.next();
            let is_last_chunk = next_chunk.is_none();
            let total_size = Ipv4Packet::minimum_packet_size() + current_chunk.len();

            let mut ip_pkg = MutableIpv4Packet::new(payload).unwrap();
            ip_pkg.set_header_length(5); // 5 is for no option fields
            ip_pkg.set_total_length(total_size as u16);
            ip_pkg.set_identification(0); // Use when implementing fragmentation
            ip_pkg.set_flags(if is_last_chunk {
                0b000 // More fragments not set
            } else {
                0b100 // More fragments set
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
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::Packet;

    use super::*;
    use test::ethernet;

    #[test]
    fn fragmented() {
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
    fn not_fragmented() {
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
        assert_eq!(ip_pkg.get_flags() == 0b100, is_fragment);
        assert_eq!(ip_pkg.get_fragment_offset() * 8, offset);
        let payload = ip_pkg.payload();
        assert_eq!(payload[0], first);
        assert_eq!(payload[payload_len - 1], last);
        ip_pkg.get_identification()
    }
}
