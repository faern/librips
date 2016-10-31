use std::io;
use std::net::{SocketAddr, ToSocketAddrs};

// mod cachemap;
// pub use util::cachemap::CacheMap;

mod buffer;

pub use util::buffer::Buffer;

pub fn first_socket_addr<A: ToSocketAddrs>(addr: A) -> io::Result<SocketAddr> {
    if let Some(addr) = try!(addr.to_socket_addrs()).next() {
        Ok(addr)
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidInput,
                           "Given ToSocketAddrs did not yield any address".to_owned()))
    }
}
