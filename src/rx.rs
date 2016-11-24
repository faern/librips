use RxResult;

use pnet::datalink::EthernetDataLinkReceiver;
use pnet::packet::ethernet::EthernetPacket;

use std::thread;
use std::time::SystemTime;

pub trait RxListener: Send {
    fn recv(&mut self, time: SystemTime, packet: &EthernetPacket) -> RxResult;
}

pub fn spawn<L>(receiver: Box<EthernetDataLinkReceiver>, listener: L)
    where L: RxListener + 'static
{
    let rx_thread = RxThread::new(receiver, listener);
    thread::spawn(move || {
        rx_thread.run();
    });
}

struct RxThread<L: RxListener> {
    receiver: Box<EthernetDataLinkReceiver>,
    listener: L,
}

impl<L: RxListener> RxThread<L> {
    pub fn new(receiver: Box<EthernetDataLinkReceiver>, listener: L) -> Self {
        RxThread {
            receiver: receiver,
            listener: listener,
        }
    }

    fn run(mut self) {
        let mut rx_iter = self.receiver.iter();
        loop {
            match rx_iter.next() {
                Ok(packet) => {
                    let time = SystemTime::now();
                    if let Err(e) = self.listener.recv(time, &packet) {
                        warn!("RxError: {:?}", e);
                    }
                }
                Err(e) => panic!("RxThread crash: {}", e),
            }
        }
    }
}
