mod icmp_rx;
mod icmp_tx;

pub use self::icmp_rx::{IcmpListener, IcmpListenerLookup, IcmpRx};
pub use self::icmp_tx::{BasicIcmpPayload, IcmpBuilder, IcmpPayload, IcmpTx, PingBuilder};


// pub struct PingSocket {
//     echo: Echo,
//     reader: Option<Receiver<Box<[u8]>>>,
//     identifier: u16,
//     sequence_number: u16,
// }

// impl PingSocket {
//     pub fn bind(str, stack?) -> PingSocket {
//
//     }
//
//     pub fn send_to();
//
//     pub fn recv();
//
//     pub fn take_recv() -> Result<Receiver<Box<[u8]>>, ()>;
// }
