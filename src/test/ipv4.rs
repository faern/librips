use std::sync::mpsc;
use std::time::SystemTime;

use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

use ipv4::Ipv4Listener;
use RxResult;

pub struct MockIpv4Listener {
    pub tx: mpsc::Sender<Vec<u8>>,
}

impl Ipv4Listener for MockIpv4Listener {
    fn recv(&mut self, _time: SystemTime, packet: Ipv4Packet) -> RxResult<()> {
        println!("MockIpv4Listener got a packet!");
        self.tx.send(packet.packet().to_vec()).unwrap();
        Ok(())
    }
}
