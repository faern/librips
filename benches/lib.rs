#![feature(test)]

extern crate test;

extern crate pnet;
extern crate ipnetwork;
extern crate rips;

use test::{Bencher, black_box};

use std::sync::{Arc, Mutex};
use std::net::Ipv4Addr;

use ipnetwork::Ipv4Network;
use pnet::util::MacAddr;

use rips::udp::UdpSocket;
use rips::testing;

#[bench]
fn bench_udp_send_to_local_lan_63k(b: &mut Bencher) {
    let mut socket = setup_socket();
    let buffer = vec![0; 1024*63];
    b.iter(|| {
        socket.send_to(black_box(&buffer), "10.137.8.1:9999").unwrap()
    });
}

#[bench]
fn bench_udp_send_to_through_gw_63k(b: &mut Bencher) {
    let mut socket = setup_socket();
    let buffer = vec![0; 1024*63];
    b.iter(|| {
        socket.send_to(black_box(&buffer), "10.137.8.2:9999").unwrap()
    });
}

#[bench]
fn bench_udp_send_to_local_lan_1byte(b: &mut Bencher) {
    let mut socket = setup_socket();
    let buffer = vec![0; 1];
    b.iter(|| {
        socket.send_to(black_box(&buffer), "10.137.8.1:9999").unwrap()
    });
}

#[bench]
fn bench_udp_send_to_through_gw_1byte(b: &mut Bencher) {
    let mut socket = setup_socket();
    let buffer = vec![0; 1];
    b.iter(|| {
        socket.send_to(black_box(&buffer), "10.137.8.2:9999").unwrap()
    });
}

fn setup_socket() -> UdpSocket {
    let (mut stack, interface, _, _) = testing::dummy_stack(0);
    stack.add_ipv4(&interface, Ipv4Network::from_cidr("10.137.8.26/32").unwrap()).unwrap();
    {
        let default =  Ipv4Network::from_cidr("0.0.0.0/0").unwrap();
        let routing_table = stack.routing_table();
        routing_table.add_route(default, Some(Ipv4Addr::new(10, 137, 8, 1)), interface.clone());
    }
    {
        let mut arp = stack.arp_table(&interface).unwrap();
        arp.insert(Ipv4Addr::new(10, 137, 8, 1), MacAddr::new(0,0,0,0,0,0));
        arp.insert(Ipv4Addr::new(10, 137, 8, 2), MacAddr::new(0,0,0,0,0,0));
    }
    let stack = Arc::new(Mutex::new(stack));

    UdpSocket::bind(stack, "10.137.8.26:1024").unwrap()
}
