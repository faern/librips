use std::io;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};

use ipnetwork::Ipv4Network;

use pnet::util::MacAddr;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::icmp::IcmpType;

use {EthernetChannel, Interface, RoutingTable, Tx, TxError, VersionedTx};
use ethernet;
use arp;
use ipv4;
use icmp;
use udp;

use util;

pub static DEFAULT_MTU: usize = 1500;

/// Error returned upon invalid usage or state of the stack.
#[derive(Debug)]
pub enum StackError {
    IllegalArgument,
    NoRouteToHost,
    InvalidInterface,
    PoisonedLock,
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
            StackError::IllegalArgument => other("Illegal argument".to_owned()),
            StackError::NoRouteToHost => other("No route to host".to_owned()),
            StackError::InvalidInterface => other("Invalid interface".to_owned()),
            StackError::PoisonedLock => other("Poisoned lock".to_owned()),
            StackError::IoError(io_e) => io_e,
            StackError::TxError(txe) => txe.into(),
        }
    }
}

pub type StackResult<T> = Result<T, StackError>;

struct Ipv4Data {
    net: Ipv4Network,
    udp_listeners: Arc<Mutex<udp::UdpListenerLookup>>,
    icmp_listeners: Arc<Mutex<icmp::IcmpListenerLookup>>,
}

/// Represents the stack on one physical interface.
/// The larger `NetworkStack` comprises multiple of these.
pub struct StackInterface {
    interface: Interface,
    mtu: usize,
    tx: Arc<Mutex<VersionedTx>>,
    arp_table: arp::ArpTable,
    ipv4s: HashMap<Ipv4Addr, Ipv4Data>,
    ipv4_listeners: Arc<Mutex<ipv4::IpListenerLookup>>,
}

impl StackInterface {
    pub fn new(interface: Interface, channel: EthernetChannel) -> StackInterface {
        let sender = channel.0;
        let receiver = channel.1;

        let vtx = Arc::new(Mutex::new(VersionedTx::new(sender)));

        let arp_table = arp::ArpTable::new();
        let arp_rx = arp_table.arp_rx(vtx.clone());

        let ipv4_listeners = Arc::new(Mutex::new(HashMap::new()));
        let ipv4_rx = ipv4::Ipv4Rx::new(ipv4_listeners.clone());

        let ethernet_listeners = vec![arp_rx, ipv4_rx];
        ethernet::EthernetRx::new(ethernet_listeners).spawn(receiver);

        StackInterface {
            interface: interface,
            mtu: DEFAULT_MTU,
            tx: vtx,
            arp_table: arp_table,
            ipv4s: HashMap::new(),
            ipv4_listeners: ipv4_listeners,
        }
    }

    pub fn interface(&self) -> &Interface {
        &self.interface
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
        match self.ipv4s.entry(ip) {
            Entry::Occupied(_) => Err(StackError::IllegalArgument),
            Entry::Vacant(entry) => {
                let mut proto_listeners = HashMap::new();

                let udp_listeners = Arc::new(Mutex::new(HashMap::new()));
                let udp_rx = udp::UdpRx::new(udp_listeners.clone());
                let udp_ipv4_listener = Box::new(udp_rx) as Box<ipv4::Ipv4Listener>;
                proto_listeners.insert(IpNextHeaderProtocols::Udp, udp_ipv4_listener);

                let icmp_listeners = Arc::new(Mutex::new(HashMap::new()));
                let icmp_rx = icmp::IcmpRx::new(icmp_listeners.clone());
                let icmp_listener = Box::new(icmp_rx) as Box<ipv4::Ipv4Listener>;
                proto_listeners.insert(IpNextHeaderProtocols::Icmp, icmp_listener);

                let mut ipv4_listeners = self.ipv4_listeners.lock().unwrap();
                ipv4_listeners.insert(ip, proto_listeners);
                let data = Ipv4Data {
                    net: ip_net,
                    udp_listeners: udp_listeners,
                    icmp_listeners: icmp_listeners,
                };

                entry.insert(data);
                Ok(())
            }
        }
    }

    pub fn ipv4_tx(&mut self, dst: Ipv4Addr, gw: Option<Ipv4Addr>) -> StackResult<ipv4::Ipv4Tx> {
        let local_dst = gw.unwrap_or(dst);
        if let Some(src) = self.closest_local_ip(local_dst) {
            let dst_mac = match self.arp_table.get(local_dst) {
                Ok(mac) => mac,
                Err(rx) => {
                    try!(tx_send!(|| self.arp_tx(); src, local_dst));
                    rx.recv().unwrap()
                }
            };
            let ethernet_tx = self.ethernet_tx(dst_mac);
            Ok(ipv4::Ipv4Tx::new(ethernet_tx, src, dst, self.mtu))
        } else {
            Err(StackError::IllegalArgument)
        }
    }

    pub fn get_mtu(&self) -> usize {
        self.mtu
    }

    pub fn set_mtu(&mut self, mtu: usize) -> StackResult<()> {
        self.mtu = mtu;
        try!(self.tx.lock().or(Err(StackError::PoisonedLock))).inc();
        Ok(())
    }

    fn closest_local_ip(&self, dst: Ipv4Addr) -> Option<Ipv4Addr> {
        for (ip, ip_data) in &self.ipv4s {
            if ip_data.net.contains(dst) {
                return Some(*ip);
            }
        }
        self.ipv4s.keys().next().cloned()
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
        match self.interfaces.entry(interface) {
            Entry::Occupied(_) => Err(StackError::InvalidInterface),
            Entry::Vacant(entry) => {
                let interface = entry.key().clone();
                entry.insert(StackInterface::new(interface, channel));
                Ok(())
            }
        }
    }

    pub fn interfaces(&self) -> Vec<Interface> {
        self.interfaces.keys().cloned().collect()
    }

    pub fn interface(&mut self, interface: &Interface) -> StackResult<&mut StackInterface> {
        match self.interfaces.get_mut(interface) {
            Some(i) => Ok(i),
            None => Err(StackError::InvalidInterface),
        }
    }

    pub fn interface_from_name(&mut self, name: &str) -> StackResult<&mut StackInterface> {
        for (interface, stack_interface) in &mut self.interfaces {
            if interface.name == name {
                return Ok(stack_interface);
            }
        }
        Err(StackError::InvalidInterface)
    }

    pub fn routing_table(&mut self) -> &mut RoutingTable {
        &mut self.routing_table
    }

    /// Attach a IPv4 network to a an interface.
    /// TODO: Deprecate and make the routing stuff better instead
    pub fn add_ipv4(&mut self, interface: &Interface, ip_net: Ipv4Network) -> StackResult<()> {
        try!(try!(self.interface(interface)).add_ipv4(ip_net));
        self.routing_table.add_route(ip_net, None, interface.clone());
        Ok(())
    }

    pub fn ipv4_tx(&mut self, dst: Ipv4Addr) -> StackResult<ipv4::Ipv4Tx> {
        if let Some((gw, interface)) = self.routing_table.route(dst) {
            if let Some(stack_interface) = self.interfaces.get_mut(&interface) {
                stack_interface.ipv4_tx(dst, gw)
            } else {
                Err(StackError::IllegalArgument)
            }
        } else {
            Err(StackError::NoRouteToHost)
        }
    }

    pub fn icmp_tx(&mut self, dst_ip: Ipv4Addr) -> StackResult<icmp::IcmpTx> {
        let ipv4_tx = try!(self.ipv4_tx(dst_ip));
        Ok(icmp::IcmpTx::new(ipv4_tx))
    }

    pub fn icmp_listen<L>(&mut self,
                          local_ip: Ipv4Addr,
                          icmp_type: IcmpType,
                          listener: L)
                          -> io::Result<()>
        where L: icmp::IcmpListener + 'static
    {
        if local_ip == Ipv4Addr::new(0, 0, 0, 0) {
            panic!("Rips does not support listening to all interfaces yet");
        } else {
            for stack_interface in self.interfaces.values() {
                if let Some(ip_data) = stack_interface.ipv4s.get(&local_ip) {
                    let mut icmp_listeners = ip_data.icmp_listeners.lock().unwrap();
                    icmp_listeners.entry(icmp_type).or_insert(vec![]).push(Box::new(listener));
                    return Ok(());
                }
            }
            let msg = "Bind address does not exist in stack".to_owned();
            Err(io::Error::new(io::ErrorKind::InvalidInput, msg))
        }
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
                        if let Some(ip_data) = stack_interface.ipv4s.get(local_ip) {
                            let mut udp_listeners = ip_data.udp_listeners.lock().unwrap();
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
                    let msg = "Bind address does not exist in stack".to_owned();
                    Err(io::Error::new(io::ErrorKind::InvalidInput, msg))
                }
            }
            SocketAddr::V6(_) => {
                Err(io::Error::new(io::ErrorKind::InvalidInput,
                                   "Rips does not support IPv6 yet".to_owned()))
            }
        }
    }
}

impl Default for NetworkStack {
    fn default() -> Self {
        Self::new()
    }
}
