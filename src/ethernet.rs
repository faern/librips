//! Provides functionality for reading and writing ethernet frames from and to
//! an underlying
//! network adapter.

use std::thread;
use std::collections::HashMap;
use std::time::SystemTime;

use pnet::datalink::EthernetDataLinkReceiver;
use pnet::packet::ethernet::{EtherType, EthernetPacket, MutableEthernetPacket};
use pnet::packet::MutablePacket;
use pnet::util::MacAddr;

use {RxResult, Tx, TxResult};

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

/// Transmit struct for the ethernet layer
pub struct EthernetTx {
    /// The source MAC address of frames sent from this `EthernetTx`
    pub src: MacAddr,

    /// The destination MAC address of frames sent from this `EthernetTx`
    pub dst: MacAddr,

    tx: Tx,
}

impl EthernetTx {
    /// Creates a new `EthernetTx` with the given parameters
    pub fn new(tx: Tx, src: MacAddr, dst: MacAddr) -> Self {
        EthernetTx {
            src: src,
            dst: dst,
            tx: tx,
        }
    }

    /// Send ethernet packets to the network.
    ///
    /// For every packet, all `header_size+size` bytes will be sent, no
    /// matter how small payload is provided to the `MutableEthernetPacket` in
    /// the call to `builder`. So in total `packets * (header_size+size)` bytes
    /// will be sent. This is  usually not a problem since the IP layer has the
    /// length in the header and the extra bytes should thus not cause any
    /// trouble.
    pub fn send<P: EthernetProtocol>(&mut self,
                                     packets: usize,
                                     size: usize,
                                     payload: P)
                                     -> TxResult {
        let mut builder = EthernetBuilder::new(self.src, self.dst, payload);
        let total_size = size + EthernetPacket::minimum_packet_size();
        self.tx.send(packets, total_size, |pkg| builder.build(pkg))
    }
}

/// Trait for anything wishing to be the payload of an Ethernet frame.
pub trait EthernetProtocol {
    fn ether_type(&self) -> EtherType;

    fn build(&mut self, buffer: &mut [u8]);
}

/// Struct building Ethernet frames
pub struct EthernetBuilder<P: EthernetProtocol> {
    src: MacAddr,
    dst: MacAddr,
    payload: P,
}

impl<P: EthernetProtocol> EthernetBuilder<P> {
    /// Creates a new `EthernetBuilder` with the given parameters
    pub fn new(src: MacAddr, dst: MacAddr, payload: P) -> Self {
        EthernetBuilder {
            src: src,
            dst: dst,
            payload: payload,
        }
    }

    /// Modifies `pkg` to have the correct header and payload
    pub fn build(&mut self, mut pkg: MutableEthernetPacket) {
        pkg.set_source(self.src);
        pkg.set_destination(self.dst);
        pkg.set_ethertype(self.payload.ether_type());
        self.payload.build(pkg.payload_mut());
    }
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
        for listener in listeners.into_iter() {
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
