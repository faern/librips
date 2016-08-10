use std::io;
use std::sync::mpsc;

use pnet::packet::ethernet::{MutableEthernetPacket, EthernetPacket};

use TxResult;

#[derive(Debug)]
pub struct EthernetTx {
    chan: mpsc::Sender<Box<[u8]>>,
}

impl EthernetTx {
    pub fn new() -> (EthernetTx, mpsc::Receiver<Box<[u8]>>) {
        let (tx, rx) = mpsc::channel();
        (EthernetTx {
            chan: tx,
        }, rx)
    }

    pub fn get_mtu(&self) -> usize {
        1500
    }

    pub fn send<T>(&mut self,
                   num_packets: usize,
                   payload_size: usize,
                   mut builder: T)
                   -> TxResult<()>
        where T: FnMut(&mut MutableEthernetPacket)
    {
        let total_packet_size = payload_size + EthernetPacket::minimum_packet_size();
        let mut buffer = vec![0; total_packet_size];
        {
            let mut pkg = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
            builder(&mut pkg);
        }
        self.chan.send(buffer.into_boxed_slice()).unwrap();
        Ok(())
    }
}
