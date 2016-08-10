//! Provides functionality for reading and writing ethernet frames from and to
//! an underlying
//! network adapter.

use std::io;
use std::thread;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use pnet::datalink::{EthernetDataLinkReceiver, EthernetDataLinkSender};
use pnet::packet::ethernet::{EtherType, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;

use {EthernetChannel, Interface, Tx, TxResult};

/// Anyone interested in receiving ethernet frames from `Ethernet` must
/// implement this.
pub trait EthernetListener: Send {
    /// Called by the library to deliver an `EthernetPacket` to a listener.
    fn recv(&mut self, time: SystemTime, packet: &EthernetPacket);

    fn get_ethertype(&self) -> EtherType;
}

/// A Datalink Ethernet manager taking care of one physical network interface.
#[derive(Clone)]
struct Ethernet {
    /// The `Interface` this `Ethernet` manages.
    pub interface: Interface,
    eth_tx: Arc<Mutex<Box<EthernetDataLinkSender>>>,
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

        EthernetRx::new(listeners).spawn(receiver);

        Ethernet {
            interface: interface,
            eth_tx: Arc::new(Mutex::new(sender)),
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

pub struct EthernetTx {
    pub src: MacAddr,
    pub dst: MacAddr,
    tx: Tx,
}

impl EthernetTx {
    pub fn new(tx: Tx,
               src: MacAddr,
               dst: MacAddr)
               -> EthernetTx {
        EthernetTx {
            src: src,
            dst: dst,
            tx: tx,
        }
    }

    pub fn get_mtu(&self) -> usize {
        1500
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
                   -> TxResult<()>
        where T: FnMut(&mut MutableEthernetPacket)
    {
        let total_packet_size = payload_size + EthernetPacket::minimum_packet_size();
        let (src, dst) = (self.src, self.dst);
        let mut builder_wrapper = |mut pkg: MutableEthernetPacket| {
            // Fill in data we are responsible for
            pkg.set_source(src);
            pkg.set_destination(dst);
            // Let the user set fields and payload
            builder(&mut pkg);
        };
        self.tx.send(num_packets, total_packet_size, &mut builder_wrapper)
    }
}

pub struct EthernetRx {
    listeners: HashMap<EtherType, Vec<Box<EthernetListener>>>,
}

impl EthernetRx {
    pub fn new(listeners: Vec<Box<EthernetListener>>) -> EthernetRx {
        let map_listeners = Self::expand_listeners(listeners);
        EthernetRx {
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
                Err(e) => panic!("EthernetRx crash: {}", e),
            }
        }
        println!("EthernetRx exits main loop");
    }
}
