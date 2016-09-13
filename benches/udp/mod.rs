use test::{Bencher, black_box};

use std::sync::{Arc, Mutex};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket as StdUdpSocket};
use std::str::FromStr;
use std::time::Duration;
use std::thread;

use ipnetwork::Ipv4Network;
use pnet::util::MacAddr;

use rips::{self, testing, NetworkStack};
use rips::udp::UdpSocket as RipsUdpSocket;

lazy_static! {
    static ref SRC_NET: Ipv4Network = Ipv4Network::from_cidr("10.0.0.3/32").unwrap();
    static ref SRC: SocketAddrV4 = SocketAddrV4::from_str("10.0.0.3:36959").unwrap();
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
    bench_to_send!(b,
                   rips_socket(testing::dummy_stack(0).0),
                   BUF_63K,
                   *DST);
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
    bench_to_send!(b,
                   rips_socket(testing::dummy_stack(0).0),
                   BUF_63K,
                   *DST2);
}

#[bench]
fn dummy_lan_1byte(b: &mut Bencher) {
    bench_to_send!(b,
                   rips_socket(testing::dummy_stack(0).0),
                   BUF_1BYTE,
                   *DST);
}

#[bench]
fn dummy_through_gw_1byte(b: &mut Bencher) {
    bench_to_send!(b,
                   rips_socket(testing::dummy_stack(0).0),
                   BUF_1BYTE,
                   *DST2);
}

#[bench]
fn std_through_gw_1byte(b: &mut Bencher) {
    bench_to_send!(b,
                   StdUdpSocket::bind(*SRC).unwrap(),
                   BUF_1BYTE,
                   *DST2);
}

fn rips_socket(mut stack: NetworkStack) -> RipsUdpSocket {
    let interface = stack.interfaces().into_iter().filter(|i| i.name.starts_with("eth")).next().expect("No suitable interface");
    stack.add_ipv4(&interface, *SRC_NET).unwrap();
    {
        let routing_table = stack.routing_table();
        routing_table.add_route(*DEFAULT_ROUTE, Some(Ipv4Addr::new(10, 137, 8, 1)), interface.clone());
    }
    {
        let mut arp = stack.arp_table(&interface).unwrap();
        arp.insert(Ipv4Addr::new(10, 137, 8, 1), MacAddr::new(0,0,0,0,0,0));
        arp.insert(Ipv4Addr::new(10, 137, 8, 2), MacAddr::new(0,0,0,0,0,0));
    }
    let stack = Arc::new(Mutex::new(stack));
    RipsUdpSocket::bind(stack, *SRC).unwrap()
}
