use std::sync::mpsc;
use std::time::SystemTime;

use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::Packet;

use ipv4::Ipv4Listener;
use {RxResult, TxResult};

pub struct MockIpv4Listener {
    pub tx: mpsc::Sender<Vec<u8>>,
}

impl Ipv4Listener for MockIpv4Listener {
    fn recv(&mut self, _time: SystemTime, packet: Ipv4Packet) -> RxResult {
        println!("MockIpv4Listener got a packet!");
        self.tx.send(packet.packet().to_vec()).unwrap();
        Ok(())
    }
}

pub struct Ipv4Tx {
    chan: mpsc::Sender<(IpNextHeaderProtocol, Box<[u8]>)>,
}

impl Ipv4Tx {
    pub fn new() -> (Ipv4Tx, mpsc::Receiver<(IpNextHeaderProtocol, Box<[u8]>)>) {
        let (tx, rx) = mpsc::channel();
        let ipv4 = Ipv4Tx { chan: tx };
        (ipv4, rx)
    }

    pub fn send<T>(&mut self,
                   payload_size: u16,
                   next_level_protocol: IpNextHeaderProtocol,
                   mut builder: T)
                   -> TxResult
        where T: FnMut(&mut [u8])
    {
        let mut buffer = vec![0; payload_size as usize];
        builder(&mut buffer);
        self.chan.send((next_level_protocol, buffer.into_boxed_slice())).unwrap();
        Ok(())
    }
}
