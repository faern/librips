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
    use RxError;

    use pnet::packet::Packet;
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};

    use rx::RxListener;

    use std::sync::mpsc;
    use std::time::SystemTime;

    use super::*;

    #[test]
    fn basic_ethernet_listener_ether_type() {
        let (tx, _) = mpsc::channel();
        let testee = BasicEthernetListener::new(EtherTypes::Ipv4, tx);
        assert_eq!(EtherTypes::Ipv4, testee.ether_type());
    }

    #[test]
    fn basic_ethernet_listener_recv() {
        let time = SystemTime::now();
        let mut packet = MutableEthernetPacket::owned(vec![0; 14]).unwrap();
        packet.set_ethertype(EtherTypes::Arp);

        let (tx, rx) = mpsc::channel();
        let mut testee = BasicEthernetListener::new(EtherTypes::Ipv4, tx);

        testee.recv(time, &packet.to_immutable()).unwrap();
        let (output_time, output_packet) = rx.try_recv().unwrap();

        assert_eq!(time, output_time);
        assert_eq!(EtherTypes::Arp, output_packet.get_ethertype());
    }

    #[test]
    fn basic_ethernet_listener_recv_closed_listener() {
        let packet = EthernetPacket::owned(vec![0; 14]).unwrap();

        let (tx, _) = mpsc::channel();
        let mut testee = BasicEthernetListener::new(EtherTypes::Ipv4, tx);

        assert!(testee.recv(SystemTime::now(), &packet).is_err());
    }


    #[test]
    #[should_panic]
    fn ethernet_rx_multiple_listener_panic() {
        let listener1 = BasicEthernetListener::new(EtherTypes::Arp, mpsc::channel().0);
        let listener2 = BasicEthernetListener::new(EtherTypes::Arp, mpsc::channel().0);
        let _testee = EthernetRx::new(vec![listener1, listener2]);
    }

    #[test]
    fn ethernet_rx_recv_no_listener() {
        let packet = EthernetPacket::owned(vec![0; 14]).unwrap();
        let mut testee = EthernetRx::new(vec![]);
        match testee.recv(SystemTime::now(), &packet) {
            Err(RxError::NoListener(_)) => (),
            _ => panic!("Expected NoListener error"),
        }
    }

    #[test]
    fn ethernet_rx_recv() {
        let time = SystemTime::now();
        let mut packet = MutableEthernetPacket::owned(vec![0; 15]).unwrap();
        packet.set_ethertype(EtherTypes::Arp);
        packet.set_payload(&[56]);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let listener1 = BasicEthernetListener::new(EtherTypes::Arp, tx1);
        let listener2 = BasicEthernetListener::new(EtherTypes::Ipv4, tx2);

        let mut testee = EthernetRx::new(vec![listener1, listener2]);
        testee.recv(time, &packet.to_immutable()).unwrap();

        assert!(rx2.try_recv().is_err());
        let (output_time, output_packet) = rx1.try_recv().unwrap();
        assert_eq!(time, output_time);
        assert_eq!(EtherTypes::Arp, output_packet.get_ethertype());
        assert_eq!([56], output_packet.payload());
    }
}
