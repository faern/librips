//! Provides functionality for reading and writing ethernet frames from and to an underlying
//! network adapter.

use std::io;
use std::thread;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};

use pnet::datalink::{Config, EthernetDataLinkSender, EthernetDataLinkReceiver};
use pnet::util::NetworkInterface;
use pnet::packet::ethernet::{EthernetPacket, EtherType, MutableEthernetPacket};

use internal::PnetEthernetProvider;

/// Anyone interested in receiving ethernet frames from `Ethernet` must implement this.
pub trait EthernetListener: Send {
    /// Called by the library to deliver an `EthernetPacket` to a listener.
    fn recv(&mut self, packet: EthernetPacket);
}

/// Trait for providing the ethernet layer link to this library.
/// Should not have to be used in general. The default `Ethernet::new` constructor uses the
/// default libpnet backend and the user never have to care about the provider.
pub trait EthernetProvider {
    fn channel(&mut self,
               &NetworkInterface,
               &Config)
               -> io::Result<(Box<EthernetDataLinkSender>, Box<EthernetDataLinkReceiver>)>;

    fn get_network_interfaces(&self) -> Vec<NetworkInterface>;
}

enum ReaderMsg {
    SetListener(EtherType, Box<EthernetListener>),
    Shutdown,
}


/// A Datalink Ethernet manager taking care of one physical network interface.
#[derive(Clone)]
pub struct Ethernet {
    iface: NetworkInterface,
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
    pub fn new(iface: &NetworkInterface, config: &Config) -> io::Result<Ethernet> {
        let provider = &mut PnetEthernetProvider as &mut EthernetProvider;
        Self::new_with_provider(provider, iface, config)
    }

    /// Create a new `Ethernet` with a custom provider of the datalink layer.
    /// Used for testing internaly to mock out libpnet. Can also be used to use this stack on top
    /// of some other datalink layer provider.
    ///
    /// See `Ethernet::new` documentation for details.
    pub fn new_with_provider(provider: &mut EthernetProvider,
                             iface: &NetworkInterface,
                             config: &Config)
                             -> io::Result<Ethernet> {
        assert!(iface.mac.is_some());
        let (eth_tx, eth_rx) = try!(provider.channel(&iface, config));
        let (reader_tx, reader_rx) = channel();
        EthernetReader::spawn(reader_rx, eth_rx);
        Ok(Ethernet {
            iface: iface.clone(),
            eth_tx: Arc::new(Mutex::new(eth_tx)),
            reader_chan: reader_tx,
        })
    }

    /// Get a reference to the `NetworkInterface` that is managed by this `Ethernet`
    pub fn get_network_interface(&self) -> &NetworkInterface {
        &self.iface
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
        let mac = self.iface.mac.as_ref().unwrap();
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
