use {RxError, RxResult};
use ethernet::EthernetListener;

use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum};

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use super::{MORE_FRAGMENTS, NO_FLAGS};
use util::Buffer;

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
                let mut ip_pkg = MutableIpv4Packet::owned(buffer.into_vec()).unwrap();
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
        let mut listeners = self.listeners.lock().unwrap();
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

    fn ether_type(&self) -> EtherType {
        EtherTypes::Ipv4
    }
}
