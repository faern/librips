use ::{TxResult, TxError, Tx};

use pnet::datalink::EthernetDataLinkSender;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::MutablePacket;

use std::sync::{Arc, Mutex};
use std::io;

/// Internal representation of of a sending channel used for synchronization.
/// Public only because it's part of the interface of other public structs.
pub struct TxBarrier {
    tx: Box<EthernetDataLinkSender>,
    version: u64,
}

impl TxBarrier {
    /// Creates a new `TxBarrier` based on the given `EthernetDataLinkSender`.
    pub fn new(tx: Box<EthernetDataLinkSender>) -> TxBarrier {
        TxBarrier {
            tx: tx,
            version: 0,
        }
    }

    /// Increments the internal counter by one. Used to invalidate all `Tx`
    /// instances created towards this `TxBarrier`
    pub fn inc(&mut self) {
        self.version = self.version.wrapping_add(1);
        trace!("TxBarrier ticked to {}", self.version);
    }

    fn io_result_to_tx_result(&self, r: Option<io::Result<()>>) -> TxResult {
        match r {
            None => Err(TxError::Other("Insufficient buffer space".to_owned())),
            Some(ior) => {
                match ior {
                    Err(e) => Err(TxError::from(e)),
                    Ok(()) => Ok(()),
                }
            }
        }
    }
}

impl Tx for TxBarrier {
    fn send<T>(&mut self, num_packets: usize, packet_size: usize, mut builder: T) -> TxResult
        where T: FnMut(&mut [u8])
    {
        let mut eth_builder = |mut packet: MutableEthernetPacket| {
            builder(packet.packet_mut());
        };
        let result = self.tx.build_and_send(num_packets, packet_size, &mut eth_builder);
        self.io_result_to_tx_result(result)
    }
}

/// Base representation of a the sending part of an interface. This is what an
/// `EthernetTx` send to.
pub struct TxImpl {
    tx: Arc<Mutex<TxBarrier>>,
    version: u64,
}

impl TxImpl {
    pub fn new(tx: Arc<Mutex<TxBarrier>>, version: u64) -> Self {
        TxImpl {
            tx: tx,
            version: version,
        }
    }
}

impl Tx for TxImpl {
    /// Sends packets to the backing `EthernetDataLinkSender`. If this `Tx` is
    /// versioned the
    /// `TxBarrier` will first be locked and the revision compared. If the
    /// revision changed
    /// this method will return `TxError::InvalidTx` instead of sending
    /// anything.
    fn send<T>(&mut self, num_packets: usize, packet_size: usize, builder: T) -> TxResult
        where T: FnMut(&mut [u8])
    {
        let mut tx = self.tx.lock().unwrap();
        if self.version != tx.version {
            Err(TxError::InvalidTx)
        } else {
            tx.send(num_packets, packet_size, builder)
        }
    }
}
