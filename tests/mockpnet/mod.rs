use std::io;
use std::sync::mpsc::{self, Sender, Receiver};
use std::thread;
use std::time;

use pnet;
use pnet::datalink::{EthernetDataLinkSender, EthernetDataLinkReceiver,
                     EthernetDataLinkChannelIterator};
use pnet::packet::ethernet::{MutableEthernetPacket, EthernetPacket};
use pnet::util::{NetworkInterface, MacAddr};
use pnet::packet::Packet;

use rips::ethernet::{EthernetListener, EthernetProvider};

pub fn dummy_iface(i: u8) -> NetworkInterface {
    NetworkInterface {
        name: format!("eth{}", i),
        index: i as u32,
        mac: Some(MacAddr::new(1, 2, 3, 4, 5, 6 + i)),
        ips: None,
        flags: 0,
    }
}

pub fn dummy_conf() -> pnet::datalink::Config {
    pnet::datalink::Config::default()
}

pub struct MockPnet {
    /// All packets that should be read from the mock network
    in_packets: Option<Receiver<io::Result<Box<[u8]>>>>,
    /// All packets leaving for the mock network will be sent to this channel
    out_channel: Option<Sender<Vec<u8>>>,
}

impl MockPnet {
    /// Create a new MockPnet.
    /// All packets sent to the `Sender` side of `in_packets` will be injected in the networkstack.
    /// All packets that librips emit will be available on the `Receiver` side of out_channel
    pub fn new(in_packets: Option<Receiver<io::Result<Box<[u8]>>>>,
               out_channel: Option<Sender<Vec<u8>>>)
               -> MockPnet {
        MockPnet {
            in_packets: in_packets,
            out_channel: out_channel,
        }
    }
}

impl EthernetProvider for MockPnet {
    fn channel(&mut self,
               _iface: &NetworkInterface,
               _config: &pnet::datalink::Config)
               -> io::Result<(Box<EthernetDataLinkSender>, Box<EthernetDataLinkReceiver>)> {
        let sender = Box::new(MockEthernetDataLinkSender { out_channel: self.out_channel.take() });
        let receiver = Box::new(MockEthernetDataLinkReceiver {
            in_packets: Some(match self.in_packets.take() {
                Some(chan) => chan,
                None => {
                    // When no Receiver for test packets are supplied use an empty one.
                    let (_, rx) = mpsc::channel();
                    rx
                }
            }),
        });

        Ok((sender, receiver))
    }

    fn get_network_interfaces(&self) -> Vec<NetworkInterface> {
        vec![dummy_iface(0), dummy_iface(1)]
    }
}


pub struct MockEthernetDataLinkSender {
    out_channel: Option<Sender<Vec<u8>>>,
}

impl EthernetDataLinkSender for MockEthernetDataLinkSender {
    fn build_and_send(&mut self,
                      _num_packets: usize,
                      packet_size: usize,
                      func: &mut FnMut(MutableEthernetPacket))
                      -> Option<io::Result<()>> {
        let mut buffer = vec![0; packet_size];
        {
            let pkg = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
            func(pkg);
        }
        if let Some(chan) = self.out_channel.as_ref() {
            chan.send(buffer).unwrap();
        }
        Some(Ok(()))
    }

    fn send_to(&mut self,
               _packet: &EthernetPacket,
               _dst: Option<NetworkInterface>)
               -> Option<io::Result<()>> {
        panic!("Not implemented in mock");
    }
}


pub struct MockEthernetDataLinkReceiver {
    in_packets: Option<Receiver<io::Result<Box<[u8]>>>>,
}

impl EthernetDataLinkReceiver for MockEthernetDataLinkReceiver {
    fn iter<'a>(&'a mut self) -> Box<EthernetDataLinkChannelIterator + 'a> {
        Box::new(MockEthernetDataLinkChannelIterator {
            in_packets: self.in_packets.take().expect("Only one receiver allowed"),
            used_packets: vec![],
        })
    }
}

pub struct MockEthernetDataLinkChannelIterator {
    in_packets: Receiver<io::Result<Box<[u8]>>>,
    used_packets: Vec<Box<[u8]>>,
}

impl<'a> EthernetDataLinkChannelIterator<'a> for MockEthernetDataLinkChannelIterator {
    fn next(&mut self) -> io::Result<EthernetPacket> {
        match self.in_packets.recv() {
            Ok(result) => {
                match result {
                    Ok(buffer) => {
                        self.used_packets.push(buffer);
                        let buffer_ref = &*self.used_packets[self.used_packets.len() - 1];
                        let packet = EthernetPacket::new(buffer_ref).unwrap();
                        Ok(packet)
                    }
                    Err(e) => Err(e),
                }
            }
            Err(_) => {
                // When we run out of test packets we sleep forever.
                loop {
                    thread::sleep(time::Duration::new(1, 0));
                }
            }
        }
    }
}

pub struct MockEthernetListener {
    pub tx: Sender<Vec<u8>>,
}

impl EthernetListener for MockEthernetListener {
    fn recv(&mut self, packet: EthernetPacket) {
        self.tx.send(packet.packet().to_vec()).unwrap();
    }
}
