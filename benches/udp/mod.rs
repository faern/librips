

use ipnetwork::Ipv4Network;
use pnet::packet::MutablePacket;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::util::MacAddr;

use rips::{self, NetworkStack, testing};
use rips::udp::UdpSocket as RipsUdpSocket;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket as StdUdpSocket};
use std::str::FromStr;

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use test::{Bencher, black_box};

lazy_static! {
    static ref LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
    static ref LOCAL_NET: Ipv4Network = Ipv4Network::new(*LOCAL_IP, 32).unwrap();
    static ref SRC: SocketAddrV4 = SocketAddrV4::from_str("10.0.0.3:36959").unwrap();
    static ref REMOTE_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    static ref DST: SocketAddrV4 = SocketAddrV4::from_str("10.0.0.1:9999").unwrap();
    static ref DST2: SocketAddrV4 = SocketAddrV4::from_str("192.168.0.1:9999").unwrap();
    static ref DEFAULT_ROUTE: Ipv4Network = Ipv4Network::from_cidr("0.0.0.0/0").unwrap();
    static ref BUF_63K: Vec<u8> = vec![0; 1024*63];
    static ref BUF_1BYTE: Vec<u8> = vec![0; 1];
}

macro_rules! bench_to_send {
    ($bencher:expr, $create_socket:expr, $buffer:ident, $dst:expr) => {{
        thread::sleep(Duration::new(0, 250_000_000));
        let mut socket = $create_socket;
        $bencher.iter(|| {
            socket.send_to(black_box(&$buffer), $dst).expect("Unablet to send")
        });
    }};
}

#[bench]
fn dummy_lan_63k(b: &mut Bencher) {
    bench_to_send!(b, rips_socket(testing::dummy_stack(0).0), BUF_63K, *DST);
}

#[bench]
fn datalink_lan_63k(b: &mut Bencher) {
    bench_to_send!(b,
                   rips_socket(rips::default_stack().expect("Unable to create default stack")),
                   BUF_63K,
                   *DST);
}

#[bench]
fn std_lan_63k(b: &mut Bencher) {
    bench_to_send!(b,
                   StdUdpSocket::bind(*SRC).expect("Unable to bind local socket"),
                   BUF_63K,
                   *DST);
}

#[bench]
fn dummy_through_gw_63k(b: &mut Bencher) {
    bench_to_send!(b, rips_socket(testing::dummy_stack(0).0), BUF_63K, *DST2);
}

#[bench]
fn dummy_lan_1byte(b: &mut Bencher) {
    bench_to_send!(b, rips_socket(testing::dummy_stack(0).0), BUF_1BYTE, *DST);
}

#[bench]
fn dummy_through_gw_1byte(b: &mut Bencher) {
    bench_to_send!(b, rips_socket(testing::dummy_stack(0).0), BUF_1BYTE, *DST2);
}

#[bench]
fn std_through_gw_1byte(b: &mut Bencher) {
    bench_to_send!(b, StdUdpSocket::bind(*SRC).unwrap(), BUF_1BYTE, *DST2);
}

#[bench]
fn dummy_recv(b: &mut Bencher) {
    let (stack, _, inject_handle, _) = testing::dummy_stack(0);
    let socket = rips_socket(stack);
    let mut buffer = vec![0; 100];
    {
        let mut pkg = MutableEthernetPacket::new(&mut buffer).unwrap();
        let mut ip_pkg = MutableIpv4Packet::new(pkg.payload_mut()).unwrap();
        ip_pkg.set_source(*REMOTE_IP);
        ip_pkg.set_destination(*LOCAL_IP);
        // SET EVERYTHING ELSE
    }
    let buffer = buffer.into_boxed_slice();
    let mut read_buffer = vec![0; 100];
    b.iter(|| {
        inject_handle.send(Ok(buffer.clone())).unwrap();
        socket.recv_from(&mut read_buffer).unwrap();
    });
}

fn rips_socket(mut stack: NetworkStack) -> RipsUdpSocket {
    let interface = stack.interfaces()
        .into_iter()
        .find(|i| i.name.starts_with("eth"))
        .expect("No suitable interface");
    stack.add_ipv4(&interface, *LOCAL_NET).unwrap();
    {
        let routing_table = stack.routing_table();
        routing_table.add_route(*DEFAULT_ROUTE,
                                Some(Ipv4Addr::new(10, 137, 8, 1)),
                                interface.clone());
    }
    {
        let mut arp = stack.interface(&interface).unwrap().arp_table();
        arp.insert(Ipv4Addr::new(10, 137, 8, 1), MacAddr::new(0, 0, 0, 0, 0, 0));
        arp.insert(Ipv4Addr::new(10, 137, 8, 2), MacAddr::new(0, 0, 0, 0, 0, 0));
    }
    let stack = Arc::new(Mutex::new(stack));
    RipsUdpSocket::bind(stack, *SRC).unwrap()
}
