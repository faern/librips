use {Protocol, RxResult, TxResult};
use ipv4::{Ipv4Listener, Ipv4Protocol, Ipv4Tx};

use pnet::packet::Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::SystemTime;
use std::net::Ipv4Addr;

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

pub struct MockIpv4Tx {
    chan: mpsc::Sender<(IpNextHeaderProtocol, Box<[u8]>)>,
}

impl MockIpv4Tx {
    pub fn new() -> (MockIpv4Tx, mpsc::Receiver<(IpNextHeaderProtocol, Box<[u8]>)>) {
        let (tx, rx) = mpsc::channel();
        let ipv4 = MockIpv4Tx { chan: tx };
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

    fn send<P: Ipv4Protocol>(&mut self, mut payload: P) -> TxResult {
        let mut buffer = vec![0; payload.len() as usize];
        payload.build(&mut buffer);
        self.chan.send((payload.next_level_protocol(), buffer.into_boxed_slice())).unwrap();
        Ok(())
    }
}

pub struct TestIpv4Protocol<'a> {
    size: usize,
    call_count: Option<&'a AtomicUsize>,
    call_bytes: Option<&'a AtomicUsize>,
}

impl<'a> TestIpv4Protocol<'a> {
    pub fn new(size: usize) -> TestIpv4Protocol<'a> {
        TestIpv4Protocol {
            size: size,
            call_count: None,
            call_bytes: None,
        }
    }

    pub fn new_counted(size: usize,
                       call_count: &'a AtomicUsize,
                       call_bytes: &'a AtomicUsize)
                       -> TestIpv4Protocol<'a> {
        TestIpv4Protocol {
            size: size,
            call_count: Some(call_count),
            call_bytes: Some(call_bytes),
        }
    }
}

impl<'a> Ipv4Protocol for TestIpv4Protocol<'a> {
    fn next_level_protocol(&self) -> IpNextHeaderProtocol {
        IpNextHeaderProtocols::Tcp
    }
}

impl<'a> Protocol for TestIpv4Protocol<'a> {
    fn len(&self) -> usize {
        self.size
    }

    fn build(&mut self, buffer: &mut [u8]) {
        let len = buffer.len();
        buffer[0] = 100;
        buffer[len - 1] = 99;
        if let Some(call_count) = self.call_count {
            call_count.fetch_add(1, Ordering::SeqCst);
        }
        if let Some(call_bytes) = self.call_bytes {
            call_bytes.fetch_add(len, Ordering::SeqCst);
        }
    }
}
