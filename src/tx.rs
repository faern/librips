use {TxResult, TxError, Tx};
use std::sync::{Arc, Mutex};
use tx_internal::TxBarrier;

/// Base representation of the sending part of an interface. This is what an
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
    fn send<T>(&mut self, num_packets: usize, packet_size: usize, builder: T) -> TxResult
        where T: FnMut(&mut [u8])
    {
        let mut tx = self.tx.lock().unwrap();
        if self.version != tx.version() {
            Err(TxError::InvalidTx)
        } else {
            tx.send(num_packets, packet_size, builder)
        }
    }
}
