use {Payload, HasPayload, BasicPayload, TxResult};
use ipv4::{Ipv4Payload, Ipv4Tx};

use pnet::packet::MutablePacket;
use pnet::packet::icmp::{IcmpCode, IcmpType, MutableIcmpPacket, checksum, IcmpTypes};
use pnet::packet::icmp::echo_request::IcmpCodes;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};

/// Trait for anything wishing to be the payload of an Icmp packet.
pub trait IcmpPayload: Payload {
    fn icmp_type(&self) -> IcmpType;

    fn icmp_code(&self) -> IcmpCode;

    fn build_header(&self, header: &mut MutableIcmpPacket);
}

pub struct BasicIcmpPayload<'a> {
    icmp_type: IcmpType,
    icmp_code: IcmpCode,
    payload: BasicPayload<'a>,
}

impl<'a> BasicIcmpPayload<'a> {
    pub fn new(icmp_type: IcmpType, icmp_code: IcmpCode, payload: &'a [u8]) -> Self {
        BasicIcmpPayload {
            icmp_type: icmp_type,
            icmp_code: icmp_code,
            payload: BasicPayload::new(payload),
        }
    }
}

impl<'a> IcmpPayload for BasicIcmpPayload<'a> {
    fn icmp_type(&self) -> IcmpType {
        self.icmp_type
    }

    fn icmp_code(&self) -> IcmpCode {
        self.icmp_code
    }

    fn build_header(&self, _header: &mut MutableIcmpPacket) {}
}

impl<'a> HasPayload for BasicIcmpPayload<'a> {
    fn get_payload(&self) -> &Payload {
        &self.payload
    }

    fn get_payload_mut(&mut self) -> &mut Payload {
        &mut self.payload
    }
}


/// Icmp packet sender struct.
pub struct IcmpTx<T: Ipv4Tx> {
    ipv4: T,
}

impl<T: Ipv4Tx> IcmpTx<T> {
    /// Creates a new `IcmpTx` based on `ipv4`
    pub fn new(ipv4: T) -> Self {
        IcmpTx { ipv4: ipv4 }
    }

    /// Sends a general Icmp packet. Should not be called directly in general,
    /// instead use the specialized `send_echo` for ping packets.
    pub fn send<P>(&mut self, payload: P) -> TxResult
        where P: IcmpPayload
    {
        let builder = IcmpBuilder::new(payload);
        self.ipv4.send(builder)
    }

    /// Sends an Echo Request packet (ping) with the given payload.
    pub fn send_echo(&mut self, payload: &[u8]) -> TxResult {
        let builder = PingBuilder::new(payload);
        println!("PingBuilder has len {}", builder.len());
        self.send(builder)
    }
}


pub struct IcmpBuilder<P: IcmpPayload> {
    builder: P,
}

impl<P: IcmpPayload> IcmpBuilder<P> {
    pub fn new(builder: P) -> IcmpBuilder<P> {
        IcmpBuilder { builder: builder }
    }
}

impl<P: IcmpPayload> Ipv4Payload for IcmpBuilder<P> {
    fn next_level_protocol(&self) -> IpNextHeaderProtocol {
        IpNextHeaderProtocols::Icmp
    }
}

impl<P: IcmpPayload> Payload for IcmpBuilder<P> {
    fn len(&self) -> usize {
        8 + self.builder.len()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        let mut pkg = MutableIcmpPacket::new(buffer).unwrap();
        {
            let mut header_pkg = MutableIcmpPacket::new(&mut pkg.packet_mut()[..8]).unwrap();
            header_pkg.set_icmp_type(self.builder.icmp_type());
            header_pkg.set_icmp_code(self.builder.icmp_code());
            self.builder.build_header(&mut header_pkg);
        }
        self.builder.build(&mut pkg.packet_mut()[8..]);
        let checksum = checksum(&pkg.to_immutable());
        pkg.set_checksum(checksum);
    }
}

pub struct PingBuilder<'a> {
    payload: BasicPayload<'a>,
}

impl<'a> PingBuilder<'a> {
    pub fn new(payload: &'a [u8]) -> PingBuilder<'a> {
        PingBuilder { payload: BasicPayload::new(payload) }
    }
}

impl<'a> IcmpPayload for PingBuilder<'a> {
    fn icmp_type(&self) -> IcmpType {
        IcmpTypes::EchoRequest
    }

    fn icmp_code(&self) -> IcmpCode {
        IcmpCodes::NoCode
    }

    fn build_header(&self, _header: &mut MutableIcmpPacket) {}
}

impl<'a> HasPayload for PingBuilder<'a> {
    fn get_payload(&self) -> &Payload {
        &self.payload
    }

    fn get_payload_mut(&mut self) -> &mut Payload {
        &mut self.payload
    }
}

#[cfg(test)]
mod tests {
    use {TxResult, TxError};
    use ipv4::{Ipv4Payload, Ipv4Tx};

    use pnet::packet::Packet;
    use pnet::packet::icmp::IcmpTypes;
    use pnet::packet::icmp::echo_request::EchoRequestPacket;
    use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};

    use std::error::Error;
    use std::net::Ipv4Addr;
    use std::sync::mpsc::{self, Sender, Receiver};

    use super::*;

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
            self.tx
                .send((payload.next_level_protocol(), buffer.into_boxed_slice()))
                .map_err(|e| TxError::Other(e.description().to_owned()))?;
            Ok(())
        }
    }

    #[test]
    fn test_send_echo() {
        let (ipv4, read_handle) = MockIpv4Tx::new();
        let mut testee = IcmpTx::new(ipv4);
        testee.send_echo(&[9, 55]).unwrap();

        let (next_level_protocol, data) = read_handle.try_recv().unwrap();
        assert_eq!(IpNextHeaderProtocols::Icmp, next_level_protocol);
        let echo_pkg = EchoRequestPacket::new(&data).unwrap();
        assert_eq!(IcmpTypes::EchoRequest, echo_pkg.get_icmp_type());
        assert_eq!(0, echo_pkg.get_icmp_code().0);
        assert_eq!(61128, echo_pkg.get_checksum());
        assert_eq!([9, 55], echo_pkg.payload());
    }

}
