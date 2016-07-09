//! Provides functionality for reading and writing ethernet frames from and to an underlying
//! network adapter.

use std::io;
use std::thread;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};

use pnet::datalink::{Channel, EthernetDataLinkSender, EthernetDataLinkReceiver};
use pnet::util::MacAddr;
use pnet::packet::ethernet::{EthernetPacket, EtherType, MutableEthernetPacket};


/// Anyone interested in receiving ethernet frames from `Ethernet` must implement this.
pub trait EthernetListener: Send {
    /// Called by the library to deliver an `EthernetPacket` to a listener.
    fn recv(&mut self, packet: EthernetPacket);
}

enum ReaderMsg {
    SetListener(EtherType, Box<EthernetListener>),
    Shutdown,
}


/// A Datalink Ethernet manager taking care of one physical network interface.
#[derive(Clone)]
pub struct Ethernet {
    pub mac: MacAddr,
    eth_tx: Arc<Mutex<Box<EthernetDataLinkSender>>>,
    reader_chan: Sender<ReaderMsg>,
}

impl Ethernet {
    /// Create a new `Ethernet` running on top of libpnet's datalink layer.
    ///
    /// # Arguments
    ///
    /// * iface: The interface this `Ethernet` will listen on and send to.
    /// * tx_buffer: The desired size of the write buffer. Might be ignored by some providers.
    /// * rx_buffer: The desired size of the read buffer. Might be ignored by some providers.
    /// * listeners: Callbacks with listeners for different `EtherType`s. Incoming packets not
    ///   matching any of these `EtherType`s will be discarded.
    /// * error_listener: If reading from the network results in an `std::io::Error` it will be
    ///   sent here, returning `false` will abort the reading thread and `true` will continue.
    pub fn new(mac: MacAddr, channel: Channel) -> Ethernet {
        let (sender, receiver) = match channel {
            Channel::Ethernet(s, r) => (s, r),
            _ => panic!("Invalid datalink::Channel type"),
        };
        let (reader_tx, reader_rx) = mpsc::channel();
        EthernetReader::spawn(reader_rx, receiver);
        Ethernet {
            mac: mac,
            eth_tx: Arc::new(Mutex::new(sender)),
            reader_chan: reader_tx,
        }
    }

    pub fn set_listener<L>(&self, ethertype: EtherType, listener: L)
        where L: EthernetListener + 'static
    {
        self.reader_chan.send(ReaderMsg::SetListener(ethertype, Box::new(listener))).unwrap();
    }

    /// Send ethernet packets to the network.
    ///
    /// For every packet, all `header_size+payload_size` bytes will be sent, no matter how small
    /// payload is provided to the `MutableEthernetPacket` in the call to `builder`. So in total
    /// `num_packets * (header_size+payload_size)` bytes will be sent. This is usually not a
    /// problem since the IP layer has the length in the header and the extra bytes should thus
    /// not cause any trouble.
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
    control_rx: Receiver<ReaderMsg>,
    listeners: HashMap<EtherType, Box<EthernetListener>>,
}

impl EthernetReader {
    pub fn spawn(control_rx: Receiver<ReaderMsg>, eth_rx: Box<EthernetDataLinkReceiver>) {
        let reader = EthernetReader {
            control_rx: control_rx,
            listeners: HashMap::new(),
        };
        thread::spawn(move || {
            reader.run(eth_rx);
        });
    }

    fn run(mut self, mut eth_rx: Box<EthernetDataLinkReceiver>) {
        let mut rx_iter = eth_rx.iter();
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
    }

    /// Process control messages to the `EthernetReader`.
    /// Returns `true` when the reader should stop reading, `false` otherwise.
    fn process_control(&mut self) -> bool {
        loop {
            match self.control_rx.try_recv() {
                Ok(ReaderMsg::SetListener(eth, listener)) => {
                    self.listeners.insert(eth, listener);
                }
                Ok(ReaderMsg::Shutdown) => return true,
                Err(TryRecvError::Disconnected) => return true,
                Err(TryRecvError::Empty) => break,
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn my_unit_test() {}
}
