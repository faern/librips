
use pnet::datalink::dummy;

use rips::NetworkStack;
use rips::ethernet::Ethernet;

#[test]
fn test_networkstack_send_ethernet() {
    let iface = dummy::dummy_interface(7);
    let mac = iface.mac.unwrap();
    let config = dummy::Config::default();
    let channel = dummy::channel(&iface, config).unwrap();
    let eth = Ethernet::new(mac, channel);
    let stack = NetworkStack::new(&[eth]);

    let ethernet = stack.get_ethernet(mac).expect("Expected Ethernet");
    assert_eq!(ethernet.mac, mac);
}

#[test]
fn test_networkstack_get_invalid_ethernet() {
    let iface = dummy::dummy_interface(7);
    let mac = iface.mac.unwrap();
    let config = dummy::Config::default();
    let channel = dummy::channel(&iface, config).unwrap();
    let eth = Ethernet::new(mac, channel);
    let stack = NetworkStack::new(&[eth]);

    let ethernet = stack.get_ethernet(dummy::dummy_interface(2).mac.unwrap());
    assert!(ethernet.is_none());
}
