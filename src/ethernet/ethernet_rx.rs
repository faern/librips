use {RxResult, RxError};
use rx::RxListener;

use pnet::datalink::EthernetDataLinkReceiver;
use pnet::packet::ethernet::{EtherType, EthernetPacket};

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::time::SystemTime;

/// Anyone interested in receiving ethernet frames from an `EthernetRx` must
/// implement this.
pub trait EthernetListener: Send {
    /// Called by the library to deliver an `EthernetPacket` to a listener.
    fn recv(&mut self, time: SystemTime, packet: &EthernetPacket) -> RxResult;

    /// Should return the `EtherType` this `EthernetListener` wants to listen
    /// to. This is so that `EthernetRx` can take a list of listeners and build
    /// a map internally.
    fn get_ethertype(&self) -> EtherType;
}

/// Receiver and parser of ethernet frames. Distributes them to
/// `EthernetListener`s based on `EtherType` in the frame.
/// This is the lowest level *Rx* type. This one is operating in its
/// own thread and reads from the `pnet` backend.
pub struct EthernetRx {
    listeners: HashMap<EtherType, Box<EthernetListener>>,
}

impl EthernetRx {
    /// Constructs a new `EthernetRx` with the given listeners. Listeners can
    /// only be given to the constructor, so they can't be changed later.
    pub fn new(listeners: Vec<Box<EthernetListener>>) -> EthernetRx {
        let map_listeners = Self::expand_listeners(listeners);
        EthernetRx { listeners: map_listeners }
    }

    fn expand_listeners(listeners: Vec<Box<EthernetListener>>)
                        -> HashMap<EtherType, Box<EthernetListener>> {
        let mut map_listeners = HashMap::new();
        for listener in listeners {
            let ethertype = listener.get_ethertype();
            match map_listeners.entry(ethertype) {
                Entry::Occupied(..) => panic!("Unable to have >1 listener per EtherType"),
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
            Some(listener) => listener.recv(time, &packet),
            None => Err(RxError::NoListener(format!("Ethernet: No listener for {}", ethertype))),
        }
    }
}
