use ::{RxResult, RxError};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherType, EthernetPacket};
use ::rx::RxListener;

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::mpsc::Sender;
use std::time::SystemTime;

/// Anyone interested in receiving ethernet frames from an `EthernetRx` must
/// implement this.
pub trait EthernetListener: Send {
    /// Called by the library to deliver an `EthernetPacket` to a listener.
    fn recv(&mut self, time: SystemTime, packet: &EthernetPacket) -> RxResult;

    /// Should return the `EtherType` this `EthernetListener` wants to listen
    /// to. This is so that `EthernetRx` can take a list of listeners and build
    /// a map internally.
    fn ether_type(&self) -> EtherType;
}

pub struct BasicEthernetListener {
    ether_type: EtherType,
    tx: Sender<(SystemTime, EthernetPacket<'static>)>,
}

impl BasicEthernetListener {
    pub fn new(ether_type: EtherType,
               tx: Sender<(SystemTime, EthernetPacket<'static>)>)
               -> Box<EthernetListener> {
        Box::new(BasicEthernetListener {
            ether_type: ether_type,
            tx: tx,
        })
    }
}

impl EthernetListener for BasicEthernetListener {
    fn recv(&mut self, time: SystemTime, packet: &EthernetPacket) -> RxResult {
        let data = packet.packet().to_vec();
        let owned_packet = EthernetPacket::owned(data).unwrap();
        self.tx
            .send((time, owned_packet))
            .map_err(|_| RxError::NoListener("Remote end closed".to_owned()))
    }

    fn ether_type(&self) -> EtherType {
        self.ether_type
    }
}

/// Receiver and parser of ethernet frames. Distributes them to
/// `EthernetListener`s based on `EtherType` in the frame.
/// This is the lowest level *Rx* type.
pub struct EthernetRx {
    listeners: HashMap<EtherType, Box<EthernetListener>>,
}

impl EthernetRx {
    /// Constructs a new `EthernetRx` with the given listeners. Listeners can
    /// only be given to the constructor, so they can't be changed later.
    ///
    /// # Panics
    ///
    /// Panics if `listeners` contain multiple listeners that listens to the
    /// same ether type.
    pub fn new(listeners: Vec<Box<EthernetListener>>) -> EthernetRx {
        let map_listeners = Self::expand_listeners(listeners);
        EthernetRx { listeners: map_listeners }
    }

    fn expand_listeners(listeners: Vec<Box<EthernetListener>>)
                        -> HashMap<EtherType, Box<EthernetListener>> {
        let mut map_listeners = HashMap::new();
        for listener in listeners {
            let ethertype = listener.ether_type();
            match map_listeners.entry(ethertype) {
                Entry::Occupied(..) => panic!("Multiple listeners for EtherType {}", ethertype),
                Entry::Vacant(entry) => entry.insert(listener),
            };
        }
        map_listeners
    }
}

impl RxListener for EthernetRx {
    fn recv(&mut self, time: SystemTime, packet: &EthernetPacket) -> RxResult {
        let ethertype = packet.get_ethertype();
        match self.listeners.get_mut(&ethertype) {
            Some(listener) => listener.recv(time, packet),
            None => Err(RxError::NoListener(format!("Ethernet: No listener for {}", ethertype))),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn multiple_listener_panic() {}
}
