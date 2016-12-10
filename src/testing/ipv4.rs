use TxResult;
use ipv4::{Ipv4Payload, Ipv4Tx};

use pnet::packet::ip::IpNextHeaderProtocol;

use std::net::Ipv4Addr;
use std::sync::mpsc::{self, Sender, Receiver};

pub struct MockIpv4Tx {
    tx: Sender<(IpNextHeaderProtocol, Box<[u8]>)>,
}

impl MockIpv4Tx {
    pub fn new() -> (MockIpv4Tx, Receiver<(IpNextHeaderProtocol, Box<[u8]>)>) {
        let (tx, rx) = mpsc::channel();
        let ipv4 = MockIpv4Tx { tx: tx };
        (ipv4, rx)
    }
}

impl Ipv4Tx for MockIpv4Tx {
    fn src(&self) -> Ipv4Addr {
        Ipv4Addr::new(0, 0, 0, 0)
    }

    fn dst(&self) -> Ipv4Addr {
        Ipv4Addr::new(0, 0, 0, 0)
    }

    fn send<P: Ipv4Payload>(&mut self, mut payload: P) -> TxResult {
        let mut buffer = vec![0; payload.len() as usize];
        payload.build(&mut buffer);
        self.tx.send((payload.next_level_protocol(), buffer.into_boxed_slice())).unwrap();
        Ok(())
    }
}
