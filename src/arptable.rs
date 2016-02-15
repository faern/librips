use std::collections::HashMap;
use std::net::Ipv4Addr;

use pnet::util::MacAddr;

pub struct ArpTable {
    map: HashMap<Ipv4Addr, MacAddr>,
}

impl ArpTable {
    pub fn new() -> Self {
        ArpTable { map: HashMap::new() }
    }

    pub fn query(&self, ip: &Ipv4Addr) -> Option<&MacAddr> {
        self.map.get(ip)
    }

    pub fn insert(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        self.map.insert(ip, mac);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use pnet::util::MacAddr;

    use super::ArpTable;

    #[test]
    fn test_insert() {
        let mut arp = ArpTable::new();
        assert!(arp.query(&Ipv4Addr::new(127, 0, 0, 1)).is_none());

        arp.insert(Ipv4Addr::new(127, 0, 0, 1), MacAddr::new(1, 2, 3, 4, 5, 6));

        assert_eq!(&MacAddr::new(1, 2, 3, 4, 5, 6),
                   arp.query(&Ipv4Addr::new(127, 0, 0, 1)).unwrap());
    }

    #[test]
    fn test_insert_overwrite() {
        let mut arp = ArpTable::new();

        arp.insert(Ipv4Addr::new(127, 0, 0, 1), MacAddr::new(1, 2, 3, 4, 5, 6));
        assert_eq!(&MacAddr::new(1, 2, 3, 4, 5, 6),
                   arp.query(&Ipv4Addr::new(127, 0, 0, 1)).unwrap());

        arp.insert(Ipv4Addr::new(127, 0, 0, 1), MacAddr::new(9, 8, 7, 6, 5, 4));
        assert_eq!(&MacAddr::new(9, 8, 7, 6, 5, 4),
                   arp.query(&Ipv4Addr::new(127, 0, 0, 1)).unwrap());
    }
}
