use std::sync::mpsc;

use pnet::packet::ethernet::{EtherType, EtherTypes};

use TxResult;
use ethernet::EthernetProtocol;

#[derive(Debug)]
pub struct EthernetTx {
    chan: mpsc::Sender<Box<[u8]>>,
}

impl EthernetTx {
    pub fn new() -> (EthernetTx, mpsc::Receiver<Box<[u8]>>) {
        let (tx, rx) = mpsc::channel();
        (EthernetTx { chan: tx }, rx)
    }

    pub fn send<P: EthernetProtocol>(&mut self,
                                     packets: usize,
                                     size: usize,
                                     mut payload: P)
                                     -> TxResult {
        for _ in 0..packets {
            let mut buffer = vec![0; size];
            payload.build(&mut buffer[..]);
            self.chan.send(buffer.into_boxed_slice()).unwrap();
        }
        Ok(())
    }
}
