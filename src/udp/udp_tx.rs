use std::net::Ipv4Addr;

use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket, ipv4_checksum_adv};

use {Protocol, TxResult};

use ipv4::{Ipv4Protocol, Ipv4Tx};

pub struct UdpTx {
    src: u16,
    dst: u16,
    ipv4: Ipv4Tx,
}

impl UdpTx {
    pub fn new(ipv4: Ipv4Tx, src: u16, dst: u16) -> UdpTx {
        UdpTx {
            src: src,
            dst: dst,
            ipv4: ipv4,
        }
    }

    pub fn send(&mut self, payload: &[u8]) -> TxResult {
        let (src_port, dst_port) = (self.src, self.dst);
        let src_ip = self.ipv4.src;
        let dst_ip = self.ipv4.dst;
        let builder = UdpBuilder::new(src_ip, dst_ip, src_port, dst_port, payload);
        self.ipv4.send(builder)
    }
}

pub struct UdpBuilder<'a> {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src: u16,
    dst: u16,
    offset: usize,
    payload: &'a [u8],
}

impl<'a> UdpBuilder<'a> {
    pub fn new(src_ip: Ipv4Addr,
               dst_ip: Ipv4Addr,
               src_port: u16,
               dst_port: u16,
               payload: &'a [u8])
               -> UdpBuilder<'a> {
        UdpBuilder {
            src_ip: src_ip,
            dst_ip: dst_ip,
            src: src_port,
            dst: dst_port,
            offset: 0,
            payload: payload,
        }
    }
}

impl<'a> Ipv4Protocol for UdpBuilder<'a> {
    fn next_level_protocol(&self) -> IpNextHeaderProtocol {
        IpNextHeaderProtocols::Udp
    }
}

impl<'a> Protocol for UdpBuilder<'a> {
    fn len(&self) -> usize {
        UdpPacket::minimum_packet_size() + self.payload.len()
    }

    fn build(&mut self, buffer: &mut [u8]) {
        let payload_buffer = if self.offset == 0 {
            {
                let header_buffer = &mut buffer[..UdpPacket::minimum_packet_size()];
                let mut pkg = MutableUdpPacket::new(header_buffer).unwrap();
                pkg.set_source(self.src);
                pkg.set_destination(self.dst);
                pkg.set_length(self.len() as u16);
                let checksum =
                    ipv4_checksum_adv(&pkg.to_immutable(), self.payload, self.src_ip, self.dst_ip);
                pkg.set_checksum(checksum);
            }
            &mut buffer[UdpPacket::minimum_packet_size()..]
        } else {
            buffer
        };
        let start = self.offset;
        let end = self.offset + payload_buffer.len();
        payload_buffer.copy_from_slice(&self.payload[start..end]);
        self.offset = end;
    }
}
