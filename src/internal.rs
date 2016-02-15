use std::io;

use pnet::datalink::{Config, Channel, EthernetDataLinkSender, EthernetDataLinkReceiver};
use pnet::util::NetworkInterface;

use ethernet::EthernetProvider;

/// Used internally to use `libpnet` as the datalink layer provider
pub struct PnetEthernetProvider;

impl EthernetProvider for PnetEthernetProvider {
    fn channel(&mut self,
               iface: &NetworkInterface,
               config: &Config)
               -> io::Result<(Box<EthernetDataLinkSender>, Box<EthernetDataLinkReceiver>)> {
        use pnet::datalink::channel;
        match channel(iface, config) {
            Ok(Channel::Ethernet(sender, receiver)) => Ok((sender, receiver)),
            Ok(_) => Err(io::Error::new(io::ErrorKind::Other, "Invalid channel type")),
            Err(e) => {
                Err(io::Error::new(io::ErrorKind::Other,
                                   format!("Unable to create data link channel: {}", e)))
            }
        }
    }

    fn get_network_interfaces(&self) -> Vec<NetworkInterface> {
        use pnet::util::get_network_interfaces;
        get_network_interfaces()
    }
}
