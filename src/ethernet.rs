//! Provides functionality for reading and writing ethernet frames from and to
//! an underlying
//! network adapter.

use std::io;
use std::thread;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};

use pnet::datalink::{Channel, EthernetDataLinkReceiver, EthernetDataLinkSender};
use pnet::util::MacAddr;
use pnet::packet::ethernet::{EtherType, EthernetPacket, MutableEthernetPacket};


/// Anyone interested in receiving ethernet frames from `Ethernet` must
/// implement this.
pub trait EthernetListener: Send {
    /// Called by the library to deliver an `EthernetPacket` to a listener.
    fn recv(&mut self, packet: EthernetPacket);
}

/// A Datalink Ethernet manager taking care of one physical network interface.
#[derive(Clone)]
pub struct Ethernet {
    /// The MAC address for this `Ethernet` interface
    pub mac: MacAddr,

    eth_tx: Arc<Mutex<Box<EthernetDataLinkSender>>>,
    reader_tx: Sender<()>,
}

impl Ethernet {
    /// Creates a new `Ethernet` with a given MAC and running on top of the
    /// given pnet datalink channel.
    pub fn new(mac: MacAddr,
               channel: Channel,
               listeners: HashMap<EtherType, Box<EthernetListener>>)
               -> Ethernet {
        let (sender, receiver) = match channel {
            Channel::Ethernet(tx, rx) => (tx, rx),
            _ => panic!("Invalid datalink::Channel type"),
        };

        let (reader_tx, reader_rx) = mpsc::channel();
        let reader = EthernetReader {
            control_rx: reader_rx,
            listeners: listeners,
        };
        reader.spawn(receiver);

        Ethernet {
            mac: mac,
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
        let mac = self.mac;
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
    listeners: HashMap<EtherType, Box<EthernetListener>>,
}

impl EthernetReader {
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
                    if self.process_control() {
                        break;
                    }
                    let ethertype = pkg.get_ethertype();
                    match self.listeners.get_mut(&ethertype) {
                        Some(listener) => listener.recv(pkg),
                        None => (),
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
