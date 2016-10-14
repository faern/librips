use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::SystemTime;

use pnet::packet::icmp::{IcmpPacket, IcmpType};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

use {RxError, RxResult};
use ipv4::Ipv4Listener;

/// Trait that must be implemented by any struct who want to receive Icmp
/// packets.
pub trait IcmpListener: Send {
    /// Called by `IcmpRx` when there is a incoming packet for this listener
    fn recv(&mut self, time: SystemTime, packet: &Ipv4Packet);
}

/// Type binding for how the listeners in `IcmpRx` are structured.
pub type IcmpListenerLookup = HashMap<IcmpType, Vec<Box<IcmpListener>>>;

/// Listener and parser of Icmp packets.
pub struct IcmpRx {
    listeners: Arc<Mutex<IcmpListenerLookup>>,
}

impl IcmpRx {
    /// Constructs a new `IcmpRx` with the given listeners.
    /// Casted before return to make it easy to add to the desired `Ipv4Rx`.
    pub fn new(listeners: Arc<Mutex<IcmpListenerLookup>>) -> IcmpRx {
        IcmpRx { listeners: listeners }
    }
}

impl Ipv4Listener for IcmpRx {
    fn recv(&mut self, time: SystemTime, ip_pkg: Ipv4Packet) -> RxResult {
        let (icmp_type, _icmp_code) = {
            let icmp_pkg = IcmpPacket::new(ip_pkg.payload()).unwrap();
            (icmp_pkg.get_icmp_type(), icmp_pkg.get_icmp_code())
        };
        trace!("Icmp got a packet with {} bytes!", ip_pkg.payload().len());
        let mut listeners = self.listeners.lock().unwrap();
        if let Some(type_listeners) = listeners.get_mut(&icmp_type) {
            for listener in type_listeners {
                listener.recv(time, &ip_pkg);
            }
            Ok(())
        } else {
            Err(RxError::NoListener(format!("Icmp, {:?}", icmp_type)))
        }
    }
}
