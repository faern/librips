use RxResult;

use pnet::datalink::EthernetDataLinkReceiver;
use pnet::packet::ethernet::{EtherType, EthernetPacket};

use std::collections::HashMap;
use std::thread;
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
    listeners: HashMap<EtherType, Vec<Box<EthernetListener>>>,
}

impl EthernetRx {
    /// Constructs a new `EthernetRx` with the given listeners. Listeners can
    /// only be given to the constructor, so they can't be changed later.
    pub fn new(listeners: Vec<Box<EthernetListener>>) -> EthernetRx {
        let map_listeners = Self::expand_listeners(listeners);
        EthernetRx { listeners: map_listeners }
    }

    fn expand_listeners(listeners: Vec<Box<EthernetListener>>)
                        -> HashMap<EtherType, Vec<Box<EthernetListener>>> {
        let mut map_listeners = HashMap::new();
        for listener in listeners {
            let ethertype = listener.get_ethertype();
            map_listeners.entry(ethertype).or_insert(vec![]).push(listener);
        }
        map_listeners
    }

    /// Start a new thread and move the `EthernetRx` to it. This thread will
    /// constantly read from the given `EthernetDataLinkReceiver` and
    /// distribute the packets to its listeners.
    pub fn spawn(self, receiver: Box<EthernetDataLinkReceiver>) {
        thread::spawn(move || {
            self.run(receiver);
        });
    }

    fn run(mut self, mut receiver: Box<EthernetDataLinkReceiver>) {
        let mut rx_iter = receiver.iter();
        loop {
            match rx_iter.next() {
                Ok(pkg) => {
                    let time = SystemTime::now();
                    let ethertype = pkg.get_ethertype();
                    match self.listeners.get_mut(&ethertype) {
                        Some(listeners) => {
                            for listener in listeners {
                                if let Err(e) = listener.recv(time, &pkg) {
                                    warn!("RxError: {:?}", e);
                                }
                            }
                        }
                        None => debug!("Ethernet: No listener for {:?}", ethertype),
                    }
                }
                Err(e) => panic!("EthernetRx crash: {}", e),
            }
        }
    }
}
