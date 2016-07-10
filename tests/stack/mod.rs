
use pnet::datalink::dummy;

use rips::NetworkStack;

#[test]
fn test_networkstack_send_ethernet() {
    let (ethernet, mac, _, _) = ::dummy_ethernet(7);
    let stack = NetworkStack::new(&[ethernet]);

    let ethernet = stack.get_ethernet(mac).expect("Expected Ethernet");
    assert_eq!(ethernet.mac, mac);
}

#[test]
fn test_networkstack_get_invalid_ethernet() {
    let (ethernet, _, _, _) = ::dummy_ethernet(7);
    let stack = NetworkStack::new(&[ethernet]);

    let ethernet = stack.get_ethernet(dummy::dummy_interface(2).mac.unwrap());
    assert!(ethernet.is_none());
}
