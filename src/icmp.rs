use std::net::Ipv4Addr;
use std::io;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::icmp::{IcmpPacket, MutableIcmpPacket, checksum, icmp_types};
use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket, icmp_codes};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::MutablePacket;

use ipv4::Ipv4;

#[derive(Clone)]
pub struct Icmp {
    ipv4: Ipv4,
}

impl Icmp {
    pub fn new(ipv4: Ipv4) -> Icmp {
        Icmp { ipv4: ipv4 }
    }

    pub fn send<T>(&mut self,
                   dst_ip: Ipv4Addr,
                   payload_size: u16,
                   mut builder: T)
                   -> Option<io::Result<()>>
        where T: FnMut(&mut MutableIcmpPacket)
    {
        let total_size = IcmpPacket::minimum_packet_size() as u16 + payload_size;
        let mut builder_wrapper = |ip_pkg: &mut MutableIpv4Packet| {
            ip_pkg.set_next_level_protocol(IpNextHeaderProtocols::Icmp);

            let mut icmp_pkg = MutableIcmpPacket::new(ip_pkg.payload_mut()).unwrap();
            builder(&mut icmp_pkg);
            let checksum = checksum(&icmp_pkg.to_immutable());
            icmp_pkg.set_checksum(checksum);
        };
        self.ipv4.send(dst_ip, total_size, &mut builder_wrapper)
    }
}

pub struct Ping {
    icmp: Icmp,
}

impl Ping {
    pub fn new(icmp: Icmp) -> Ping {
        Ping { icmp: icmp }
    }

    pub fn send(&mut self, dst_ip: Ipv4Addr, payload: &[u8]) -> Option<io::Result<()>> {
        let total_size = (EchoRequestPacket::minimum_packet_size() -
                          IcmpPacket::minimum_packet_size() +
                          payload.len()) as u16;
        let mut builder_wrapper = |icmp_pkg: &mut MutableIcmpPacket| {
            icmp_pkg.set_icmp_type(icmp_types::EchoRequest);
            icmp_pkg.set_icmp_code(icmp_codes::NoCode);
            let mut echo_pkg = MutableEchoRequestPacket::new(icmp_pkg.packet_mut()).unwrap();
            echo_pkg.set_payload(payload);
        };
        self.icmp.send(dst_ip, total_size, &mut builder_wrapper)
    }
}
