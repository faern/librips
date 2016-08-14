use std::sync::mpsc;

use pnet::packet::ethernet::EtherType;

use TxResult;

#[derive(Debug)]
pub struct EthernetTx {
    chan: mpsc::Sender<Box<[u8]>>,
}

impl EthernetTx {
    pub fn new() -> (EthernetTx, mpsc::Receiver<Box<[u8]>>) {
        let (tx, rx) = mpsc::channel();
        (EthernetTx { chan: tx }, rx)
    }

    pub fn get_mtu(&self) -> usize {
        1500
    }

    pub fn send<T>(&mut self,
                   num_packets: usize,
                   payload_size: usize,
                   _ether_type: EtherType,
                   mut builder: T)
                   -> TxResult
        where T: FnMut(&mut [u8])
    {
        for _ in 0..num_packets {
            let mut buffer = vec![0; payload_size];
            builder(&mut buffer[..]);
            self.chan.send(buffer.into_boxed_slice()).unwrap();
        }
        Ok(())
    }
}
