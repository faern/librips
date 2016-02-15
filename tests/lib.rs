extern crate pnet;
extern crate rips;
extern crate pnet_packets;

// Does mocking of libpnet so we can test without actually calling that library.
mod mockpnet;

// Modules containing tests.
mod ethernet;
mod stack;
mod arp;
