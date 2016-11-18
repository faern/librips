use TxResult;
use ethernet::{EthernetProtocol, EthernetTx};

use pnet::util::MacAddr;

use std::sync::mpsc;

#[derive(Debug)]
pub struct MockEthernetTx {
    chan: mpsc::Sender<Box<[u8]>>,
}

impl MockEthernetTx {
    pub fn new() -> (MockEthernetTx, mpsc::Receiver<Box<[u8]>>) {
        let (tx, rx) = mpsc::channel();
        (MockEthernetTx { chan: tx }, rx)
    }
}

impl EthernetTx for MockEthernetTx {
    fn src(&self) -> MacAddr {
        MacAddr::new(0, 0, 0, 0, 0, 0)
    }

    fn dst(&self) -> MacAddr {
        MacAddr::new(0, 0, 0, 0, 0, 0)
    }

    fn send<P>(&mut self, packets: usize, packet_size: usize, mut payload: P) -> TxResult
        where P: EthernetProtocol
    {
        for _ in 0..packets {
            let mut buffer = vec![0; packet_size];
            payload.build(&mut buffer[..]);
            self.chan.send(buffer.into_boxed_slice()).unwrap();
        }
        Ok(())
    }
}
