use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::SystemTime;

use pnet::packet::ip::{IpNextHeaderProtocols, IpNextHeaderProtocol};
use pnet::packet::icmp::{IcmpPacket, IcmpType, IcmpCode, MutableIcmpPacket, checksum, icmp_types};
use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket, icmp_codes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::{MutablePacket, Packet};

use {RxError, RxResult, TxResult};
use ipv4::{Ipv4Listener, Ipv4Protocol};

#[cfg(all(test, feature = "unit-tests"))]
use testing::ipv4::Ipv4Tx;
#[cfg(not(all(test, feature = "unit-tests")))]
use ipv4::Ipv4Tx;

/// Trait that must be implemented by any struct who want to receive Icmp
/// packets.
pub trait IcmpListener: Send {
    /// Called by `IcmpRx` when there is a incoming packet for this listener
    fn recv(&mut self, time: SystemTime, packet: &Ipv4Packet);
}

/// Type binding for how the listeners in `IcmpRx` are structured.
pub type IcmpListenerLookup = HashMap<IcmpType, Vec<Box<IcmpListener>>>;

/// Listener and parser of Icmp packets.
pub struct IcmpRx {
    listeners: Arc<Mutex<IcmpListenerLookup>>,
}

impl IcmpRx {
    /// Constructs a new `IcmpRx` with the given listeners.
    /// Casted before return to make it easy to add to the desired `Ipv4Rx`.
    pub fn new(listeners: Arc<Mutex<IcmpListenerLookup>>) -> IcmpRx {
        IcmpRx { listeners: listeners }
    }
}

impl Ipv4Listener for IcmpRx {
    fn recv(&mut self, time: SystemTime, ip_pkg: Ipv4Packet) -> RxResult {
        let (icmp_type, _icmp_code) = {
            let icmp_pkg = IcmpPacket::new(ip_pkg.payload()).unwrap();
            (icmp_pkg.get_icmp_type(), icmp_pkg.get_icmp_code())
        };
        trace!("Icmp got a packet with {} bytes!", ip_pkg.payload().len());
        let mut listeners = self.listeners.lock().unwrap();
        if let Some(type_listeners) = listeners.get_mut(&icmp_type) {
            for listener in type_listeners {
                listener.recv(time, &ip_pkg);
            }
            Ok(())
        } else {
            Err(RxError::NoListener(format!("Icmp, {:?}", icmp_type)))
        }
    }
}

/// Icmp packet builder and sender struct.
pub struct IcmpTx {
    ipv4: Ipv4Tx,
}

impl IcmpTx {
    /// Creates a new `IcmpTx` based on `ipv4`
    pub fn new(ipv4: Ipv4Tx) -> IcmpTx {
        IcmpTx { ipv4: ipv4 }
    }

    /// Sends a general Icmp packet. Should not be called directly in general,
    /// instead use the specialized `send_echo` for ping packets.
    pub fn send<P>(&mut self, builder: P) -> TxResult
        where P: IcmpProtocol
    {
        let builder = IcmpBuilder::new(builder);
        self.ipv4.send(builder)
    }

    /// Sends an Echo Request packet (ping) with the given payload.
    pub fn send_echo(&mut self, payload: &[u8]) -> TxResult {
        let builder = PingBuilder::new(payload);
        self.send(builder)
    }
}

/// Trait for anything wishing to be the payload of an Icmp packet.
pub trait IcmpProtocol {
    fn icmp_type(&self) -> IcmpType;

    fn icmp_code(&self) -> IcmpCode;

    fn len(&self) -> u16;

    fn build(&mut self, pkg: &mut MutableIcmpPacket);
}

struct IcmpBuilder<P: IcmpProtocol> {
    builder: P,
}

impl<P: IcmpProtocol> IcmpBuilder<P> {
    pub fn new(builder: P) -> IcmpBuilder<P> {
        IcmpBuilder {
            builder: builder,
        }
    }
}

impl<P: IcmpProtocol> Ipv4Protocol for IcmpBuilder<P> {
    fn next_level_protocol(&self) -> IpNextHeaderProtocol {
        IpNextHeaderProtocols::Icmp
    }

    fn len(&self) -> u16 {
        IcmpPacket::minimum_packet_size() as u16 + self.builder.len()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        let mut pkg = MutableIcmpPacket::new(buffer).unwrap();
        pkg.set_icmp_type(self.builder.icmp_type());
        pkg.set_icmp_code(self.builder.icmp_code());
        self.builder.build(&mut pkg);
        let checksum = checksum(&pkg.to_immutable());
        pkg.set_checksum(checksum);
    }
}

struct PingBuilder<'a> {
    payload: &'a [u8],
}

impl<'a> PingBuilder<'a> {
    pub fn new(payload: &'a [u8]) -> PingBuilder<'a> {
        PingBuilder {
            payload: payload,
        }
    }
}

impl<'a> IcmpProtocol for PingBuilder<'a> {
    fn icmp_type(&self) -> IcmpType {
        icmp_types::EchoRequest
    }

    fn icmp_code(&self) -> IcmpCode {
        icmp_codes::NoCode
    }

    fn len(&self) -> u16 {
        (EchoRequestPacket::minimum_packet_size() - IcmpPacket::minimum_packet_size() + self.payload.len()) as u16
    }

    fn build(&mut self, pkg: &mut MutableIcmpPacket) {
        let mut echo_pkg = MutableEchoRequestPacket::new(pkg.packet_mut()).unwrap();
        echo_pkg.set_identifier(0);
        echo_pkg.set_sequence_number(0);
        echo_pkg.set_payload(self.payload);
    }
}

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

#[cfg(all(test, feature = "unit-tests"))]
mod tests {
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::icmp::icmp_types;
    use pnet::packet::icmp::echo_request::EchoRequestPacket;
    use pnet::packet::Packet;

    use super::*;
    use testing::ipv4::Ipv4Tx;

    #[test]
    fn test_ping() {
        let (ipv4, read_handle) = Ipv4Tx::new();
        let mut icmp = IcmpTx::new(ipv4);
        icmp.send_echo(&[9, 55]).unwrap();

        let (next_level_protocol, data) = read_handle.recv().unwrap();
        assert_eq!(next_level_protocol, IpNextHeaderProtocols::Icmp);
        let echo_pkg = EchoRequestPacket::new(&data).unwrap();
        assert_eq!(echo_pkg.get_icmp_type(), icmp_types::EchoRequest);
        assert_eq!(echo_pkg.get_icmp_code().0, 0);
        assert_eq!(echo_pkg.get_checksum(), 61128);
        assert_eq!(echo_pkg.payload(), [9, 55]);
    }
}
