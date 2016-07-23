//! Provides functionality for reading and writing ethernet frames from and to
//! an underlying
//! network adapter.

use std::io;
use std::thread;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::time::SystemTime;

use pnet::datalink::{EthernetDataLinkReceiver, EthernetDataLinkSender};
use pnet::packet::ethernet::{EtherType, EthernetPacket, MutableEthernetPacket};

use {EthernetChannel, Interface};

/// Anyone interested in receiving ethernet frames from `Ethernet` must
/// implement this.
pub trait EthernetListener: Send {
    /// Called by the library to deliver an `EthernetPacket` to a listener.
    fn recv(&mut self, time: SystemTime, packet: &EthernetPacket);

    fn get_ethertype(&self) -> EtherType;
}

/// A Datalink Ethernet manager taking care of one physical network interface.
#[derive(Clone)]
pub struct Ethernet {
    /// The `Interface` this `Ethernet` manages.
    pub interface: Interface,

    eth_tx: Arc<Mutex<Box<EthernetDataLinkSender>>>,
    reader_tx: Sender<()>,
}

impl Ethernet {
    /// Creates a new `Ethernet` with a given MAC and running on top of the
    /// given pnet datalink channel.
    pub fn new(interface: Interface,
               channel: EthernetChannel,
               listeners: Vec<Box<EthernetListener>>)
               -> Ethernet {
        let sender = channel.0;
        let receiver = channel.1;

        let (reader_tx, reader_rx) = mpsc::channel();
        EthernetReader::new(reader_rx, listeners).spawn(receiver);

        Ethernet {
            interface: interface,
            eth_tx: Arc::new(Mutex::new(sender)),
            reader_tx: reader_tx,
        }
    }

    /// Send ethernet packets to the network.
    ///
    /// For every packet, all `header_size+payload_size` bytes will be sent, no
    /// matter how small payload is provided to the `MutableEthernetPacket` in
    /// the call to `builder`. So in total `num_packets *
    /// (header_size+payload_size)` bytes will be sent. This is  usually not a
    /// problem since the IP layer has the length in the header and the extra
    /// bytes should thus not cause any trouble.
    pub fn send<T>(&mut self,
                   num_packets: usize,
                   payload_size: usize,
                   mut builder: T)
                   -> Option<io::Result<()>>
        where T: FnMut(&mut MutableEthernetPacket)
    {
        let mac = self.interface.mac;
        let mut builder_wrapper = |mut pkg: MutableEthernetPacket| {
            // Fill in data we are responsible for
            pkg.set_source(mac.clone());
            // Let the user set fields and payload
            builder(&mut pkg);
        };
        let total_packet_size = payload_size + EthernetPacket::minimum_packet_size();
        let mut locked_eth_tx = self.eth_tx.lock().expect("Unable to lock ethernet sender");
        locked_eth_tx.build_and_send(num_packets, total_packet_size, &mut builder_wrapper)
    }
}

struct EthernetReader {
    control_rx: Receiver<()>,
    listeners: HashMap<EtherType, Vec<Box<EthernetListener>>>,
}

impl EthernetReader {
    pub fn new(control_rx: Receiver<()>, listeners: Vec<Box<EthernetListener>>) -> EthernetReader {
        let map_listeners = Self::expand_listeners(listeners);
        EthernetReader {
            control_rx: control_rx,
            listeners: map_listeners,
        }
    }

    fn expand_listeners(listeners: Vec<Box<EthernetListener>>)
                        -> HashMap<EtherType, Vec<Box<EthernetListener>>> {
        let mut map_listeners = HashMap::new();
        for listener in listeners.into_iter() {
            let ethertype = listener.get_ethertype();
            if !map_listeners.contains_key(&ethertype) {
                map_listeners.insert(ethertype, vec![listener]);
            } else {
                map_listeners.get_mut(&ethertype).unwrap().push(listener);
            }
        }
        map_listeners
    }

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
                    if self.process_control() {
                        break;
                    }
                    let ethertype = pkg.get_ethertype();
                    match self.listeners.get_mut(&ethertype) {
                        Some(listeners) => {
                            for listener in listeners {
                                listener.recv(time, &pkg);
                            }
                        }
                        None => println!("Ethernet: No listener for {:?}", ethertype),
                    }
                }
                Err(e) => panic!("EthernetReader crash: {}", e),
            }
        }
        println!("EthernetReader exits main loop");
    }

    /// Process control messages to the `EthernetReader`.
    /// Returns `true` when the reader should stop reading, `false` otherwise.
    fn process_control(&mut self) -> bool {
        loop {
            match self.control_rx.try_recv() {
                Err(TryRecvError::Disconnected) => return true,
                _ => break,
            }
        }
        false
    }
}
