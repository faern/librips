use std::io;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};

use ipnetwork::Ipv4Network;

use pnet::util::MacAddr;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};

use {EthernetChannel, Interface, RoutingTable, Tx, TxError, VersionedTx};
use ethernet;
use arp;
use ipv4;
use icmp;
use udp;

use util;


#[derive(Debug)]
pub enum StackError {
    IllegalArgument,
    NoRouteToHost,
    InvalidInterface,
    TxError(TxError),
    IoError(io::Error),
}

impl From<TxError> for StackError {
    fn from(e: TxError) -> StackError {
        StackError::TxError(e)
    }
}

impl From<io::Error> for StackError {
    fn from(e: io::Error) -> StackError {
        StackError::IoError(e)
    }
}

impl From<StackError> for io::Error {
    fn from(e: StackError) -> io::Error {
        let other = |msg| io::Error::new(io::ErrorKind::Other, msg);
        match e {
            StackError::IllegalArgument => other(format!("Illegal argument")),
            StackError::InvalidInterface => other(format!("Invalid interface")),
            StackError::NoRouteToHost => other(format!("No route to host")),
            StackError::IoError(io_e) => io_e,
            StackError::TxError(txe) => txe.into(),
        }
    }
}

pub type StackResult<T> = Result<T, StackError>;

/// Represents the stack on one physical interface.
/// The larger `NetworkStack` comprises multiple of these.
struct StackInterface {
    interface: Interface,
    tx: Arc<Mutex<VersionedTx>>,
    arp_table: arp::ArpTable,
    ipv4s: HashMap<Ipv4Addr, Ipv4Network>,
    ipv4_listeners: Arc<Mutex<ipv4::IpListenerLookup>>,
    udp_listeners: HashMap<Ipv4Addr, Arc<Mutex<udp::UdpListenerLookup>>>,
}

impl StackInterface {
    pub fn new(interface: Interface, channel: EthernetChannel) -> StackInterface {
        let sender = channel.0;
        let receiver = channel.1;

        let vtx = Arc::new(Mutex::new(VersionedTx::new(sender)));

        let arp_table = arp::ArpTable::new();
        let arp_ethernet_listener = arp_table.arp_rx(vtx.clone());

        let ipv4_listeners = Arc::new(Mutex::new(HashMap::new()));
        let ipv4_ethernet_listener = ipv4::Ipv4Rx::new(ipv4_listeners.clone());

        let ethernet_listeners = vec![arp_ethernet_listener, ipv4_ethernet_listener];
        ethernet::EthernetRx::new(ethernet_listeners).spawn(receiver);

        StackInterface {
            interface: interface.clone(),
            tx: vtx,
            arp_table: arp_table,
            ipv4s: HashMap::new(),
            ipv4_listeners: ipv4_listeners,
            udp_listeners: HashMap::new(),
        }
    }

    fn tx(&self) -> Tx {
        Tx::versioned(self.tx.clone())
    }

    pub fn ethernet_tx(&self, dst: MacAddr) -> ethernet::EthernetTx {
        ethernet::EthernetTx::new(self.tx(), self.interface.mac, dst)
    }

    pub fn arp_tx(&self) -> arp::ArpTx {
        arp::ArpTx::new(self.ethernet_tx(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)))
    }

    pub fn arp_table(&self) -> arp::ArpTable {
        self.arp_table.clone()
    }

    pub fn add_ipv4(&mut self, ip_net: Ipv4Network) -> StackResult<()> {
        let ip = ip_net.ip();
        if !self.ipv4s.contains_key(&ip) {
            self.ipv4s.insert(ip, ip_net);
            let ipv4_listeners = self.create_ipv4_listeners(ip);
            let mut iface_ipv4_listeners = self.ipv4_listeners.lock().unwrap();
            iface_ipv4_listeners.insert(ip, ipv4_listeners);
            Ok(())
        } else {
            Err(StackError::IllegalArgument)
        }
    }

    pub fn ipv4_tx(&mut self, dst: Ipv4Addr, gw: Option<Ipv4Addr>) -> StackResult<ipv4::Ipv4Tx> {
        let local_dst = gw.unwrap_or(dst);
        if let Some(src) = self.closest_local_ip(local_dst) {
            let dst_mac = match self.arp_table.get(local_dst) {
                Ok(mac) => mac,
                Err(rx) => {
                    try!(self.arp_tx().send(src, dst));
                    rx.recv().unwrap()
                },
            };
            let ethernet_tx = self.ethernet_tx(dst_mac);
            Ok(ipv4::Ipv4Tx::new(ethernet_tx, src, dst))
        } else {
            Err(StackError::IllegalArgument)
        }
    }

    fn closest_local_ip(&self, dst: Ipv4Addr) -> Option<Ipv4Addr> {
        for (ip, net) in &self.ipv4s {
            if net.contains(dst) {
                return Some(*ip);
            }
        }
        None
    }

    fn create_ipv4_listeners(&mut self,
                             ip: Ipv4Addr)
                             -> HashMap<IpNextHeaderProtocol, Box<ipv4::Ipv4Listener>> {
        let mut proto_listeners = HashMap::new();

        let udp_listeners = Arc::new(Mutex::new(HashMap::new()));
        self.udp_listeners.insert(ip, udp_listeners.clone());
        let udp_rx = udp::UdpRx::new(udp_listeners);
        let udp_ipv4_listener = Box::new(udp_rx) as Box<ipv4::Ipv4Listener>;
        proto_listeners.insert(IpNextHeaderProtocols::Udp, udp_ipv4_listener);

        // Insert Icmp listener stuff

        proto_listeners
    }
}

/// The main struct of this library, managing an entire TCP/IP stack. Takes
/// care of ARP, routing tables, threads, TCP resends/fragmentation etc. Most
/// of this is still unimplemented.
pub struct NetworkStack {
    interfaces: HashMap<Interface, StackInterface>,
    routing_table: RoutingTable,
}

impl NetworkStack {
    pub fn new() -> NetworkStack {
        NetworkStack {
            interfaces: HashMap::new(),
            routing_table: RoutingTable::new(),
        }
    }

    pub fn add_interface(&mut self,
                         interface: Interface,
                         channel: EthernetChannel)
                         -> StackResult<()> {
        if self.interfaces.contains_key(&interface) {
            Err(StackError::InvalidInterface)
        } else {
            let stack_interface = StackInterface::new(interface.clone(), channel);
            self.interfaces.insert(interface, stack_interface);
            Ok(())
        }
    }

    pub fn interfaces(&self) -> Vec<&Interface> {
        self.interfaces.keys().collect()
    }

    pub fn interface_from_name(&self, name: &str) -> Option<&Interface> {
        for interface in self.interfaces.keys() {
            if interface.name == name {
                return Some(interface);
            }
        }
        None
    }

    pub fn ethernet_tx(&self, interface: &Interface, dst: MacAddr) -> Option<ethernet::EthernetTx> {
        self.interfaces.get(interface).map(|si| si.ethernet_tx(dst))
    }

    pub fn arp_tx(&self, interface: &Interface) -> Option<arp::ArpTx> {
        self.interfaces.get(interface).map(|si| si.arp_tx())
    }

    pub fn arp_table(&self, interface: &Interface) -> Option<arp::ArpTable> {
        self.interfaces.get(interface).map(|si| si.arp_table())
    }

    pub fn routing_table(&mut self) -> &mut RoutingTable {
        &mut self.routing_table
    }

    /// Attach a IPv4 network to a an interface.
    pub fn add_ipv4(&mut self, interface: &Interface, ip_net: Ipv4Network) -> StackResult<()> {
        if let Some(stack_interface) = self.interfaces.get_mut(interface) {
            let result = stack_interface.add_ipv4(ip_net);
            if result.is_ok() {
                self.routing_table.add_route(ip_net, None, interface.clone());
            }
            result
        } else {
            Err(StackError::InvalidInterface)
        }
    }

    pub fn ipv4_tx(&mut self, dst: Ipv4Addr) -> StackResult<ipv4::Ipv4Tx> {
        if let Some((gw, interface)) = self.routing_table.route(dst) {
            if let Some(stack_interface) = self.interfaces.get_mut(&interface) {
                stack_interface.ipv4_tx(dst, gw)
            } else {
                Err(StackError::IllegalArgument)
            }
        } else {
            println!("ipv4_tx illegal 2");
            Err(StackError::NoRouteToHost)
        }
    }

    pub fn icmp_tx(&mut self, dst_ip: Ipv4Addr) -> StackResult<icmp::IcmpTx> {
        let ipv4_tx = try!(self.ipv4_tx(dst_ip));
        Ok(icmp::IcmpTx::new(ipv4_tx))
    }

    pub fn udp_tx(&mut self, dst_ip: Ipv4Addr, src: u16, dst_port: u16) -> StackResult<udp::UdpTx> {
        let ipv4_tx = try!(self.ipv4_tx(dst_ip));
        Ok(udp::UdpTx::new(ipv4_tx, src, dst_port))
    }

    pub fn udp_listen<A, L>(&mut self, addr: A, listener: L) -> io::Result<SocketAddr>
        where A: ToSocketAddrs,
              L: udp::UdpListener + 'static
    {
        match try!(util::first_socket_addr(addr)) {
            SocketAddr::V4(addr) => {
                let local_ip = addr.ip();
                let local_port = addr.port();
                if local_ip == &Ipv4Addr::new(0, 0, 0, 0) {
                    panic!("Rips does not support listening to all interfaces yet");
                } else {
                    for stack_interface in self.interfaces.values() {
                        if let Some(udp_listeners) = stack_interface.udp_listeners.get(local_ip) {
                            let mut udp_listeners = udp_listeners.lock().unwrap();
                            if !udp_listeners.contains_key(&local_port) {
                                udp_listeners.insert(local_port, Box::new(listener));
                                return Ok(SocketAddr::V4(addr));
                            } else {
                                let msg = format!("Port {} is already occupied on {}",
                                                  local_port,
                                                  local_ip);
                                return Err(io::Error::new(io::ErrorKind::AddrInUse, msg));
                            }
                        }
                    }
                    let msg = format!("Bind address does not exist in stack");
                    Err(io::Error::new(io::ErrorKind::InvalidInput, msg))
                }
            }
            SocketAddr::V6(_) => {
                Err(io::Error::new(io::ErrorKind::InvalidInput,
                                   format!("Rips does not support IPv6 yet")))
            }
        }
    }
}
