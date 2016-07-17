use std::io;

use pnet::packet::ethernet::MutableEthernetPacket;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Ethernet {
    pub name: String,
}

impl Ethernet {
    pub fn new(name: &str) -> Ethernet {
        Ethernet {
            name: name.to_string(),
        }
    }

    fn send<T>(&mut self,
        _num_packets: usize,
        _payload_size: usize,
        mut _builder: T)
        -> Option<io::Result<()>>
        where T: FnMut(&mut MutableEthernetPacket) {
            panic!("Not implemented in mock");
        }
}
