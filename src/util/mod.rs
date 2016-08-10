use std::net::{ToSocketAddrs, SocketAddr};
use std::io;

//mod cachemap;

//pub use util::cachemap::CacheMap;

pub fn first_socket_addr<A: ToSocketAddrs>(addr: A) -> io::Result<SocketAddr> {
    if let Some(addr) = try!(addr.to_socket_addrs()).next() {
        Ok(addr)
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidInput,
                           format!("Given ToSocketAddrs did not yield any address")))
    }
}
