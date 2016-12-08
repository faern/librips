use ::{TxResult, TxError, Tx};

use pnet::datalink::EthernetDataLinkSender;
use pnet::packet::MutablePacket;
use pnet::packet::ethernet::MutableEthernetPacket;

use std::io;

pub struct TxBarrier {
    tx: Box<EthernetDataLinkSender>,
    version: u64,
}

impl TxBarrier {
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

    pub fn version(&self) -> u64 {
        self.version
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
