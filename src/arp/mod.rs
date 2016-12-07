use ethernet::EthernetListener;

use pnet::util::MacAddr;
use stack::StackInterfaceMsg;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use std::sync::mpsc::{self, Receiver, Sender};

mod arp_rx;
mod arp_tx;

pub use self::arp_rx::ArpRx;
pub use self::arp_tx::{ArpBuilder, ArpTx};

#[derive(Default)]
pub struct TableData {
    pub table: HashMap<Ipv4Addr, MacAddr>,
    pub listeners: HashMap<Ipv4Addr, Vec<Sender<MacAddr>>>,
}

impl TableData {
    pub fn new() -> Self {
        TableData {
            table: HashMap::new(),
            listeners: HashMap::new(),
        }
    }
}

/// The main Arp table struct. Contains the actual data behind a `Mutex` so it
/// can be shared
/// with `ArpRx` instances.
#[derive(Clone)]
pub struct ArpTable {
    data: Arc<Mutex<TableData>>,
}

impl ArpTable {
    /// Creates a new `ArpTable` with no entries in it.
    pub fn new() -> ArpTable {
        let data = Arc::new(Mutex::new(TableData::new()));
        ArpTable { data: data }
    }

    pub fn data(&self) -> Arc<Mutex<TableData>> {
        self.data.clone()
    }

    /// Creates a new `ArpRx` cast to a `Box<EthernetListener>` so that it can
    /// easily be added
    /// to a `Vec` and passed to `EthernetRx` as a listener.
    /// The `ArpRx` created here will share the table with this `ArpTable`.
    /// The given `VersionedTx` will have its revision bumped upon incoming Arp
    /// packet.
    pub fn arp_rx(&self, listener: Sender<StackInterfaceMsg>) -> Box<EthernetListener> {
        Box::new(ArpRx::new(listener)) as Box<EthernetListener>
    }

    /// Queries the table for a MAC. If it does not exist a request is sent and
    /// the call is blocked
    /// until a reply has arrived
    pub fn get(&mut self, target_ip: Ipv4Addr) -> Result<MacAddr, Receiver<MacAddr>> {
        let mut data = self.data.lock().unwrap();
        if let Some(mac) = data.table.get(&target_ip) {
            return Ok(*mac);
        }
        Err(Self::add_listener(&mut data, target_ip))
    }

    /// Manually insert an IP -> MAC mapping into this Arp table and notify all
    /// listeners for that IP. Will return `true` if this insertion changed the
    /// table.
    pub fn insert(&mut self, ip: Ipv4Addr, mac: MacAddr) -> bool {
        let mut data = self.data.lock().expect("Unable to lock Arp::table for writing");
        let old_mac = data.table.insert(ip, mac);
        if let Some(listeners) = data.listeners.remove(&ip) {
            for listener in listeners {
                listener.send(mac).unwrap_or(());
            }
        }
        old_mac.is_none() || old_mac != Some(mac)
    }

    fn add_listener(data: &mut TableData, ip: Ipv4Addr) -> Receiver<MacAddr> {
        let (tx, rx) = mpsc::channel();
        data.listeners.entry(ip).or_insert_with(Vec::new).push(tx);
        rx
    }
}

impl Default for ArpTable {
    fn default() -> Self {
        Self::new()
    }
}
