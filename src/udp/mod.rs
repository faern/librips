use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::io;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

use {TxError, TxResult};
#[cfg(not(feature = "unit-tests"))]
use {NetworkStack, StackError, StackResult};

use util;

mod udp_rx;
mod udp_tx;

pub use self::udp_rx::{UdpListener, UdpListenerLookup, UdpRx};
pub use self::udp_tx::{UdpTx, UdpBuilder};

use self::udp_rx::UdpSocketReader;

#[cfg(not(feature = "unit-tests"))]
pub struct UdpSocket {
    socket_addr: SocketAddr,
    stack: Arc<Mutex<NetworkStack>>,
    tx_cache: HashMap<SocketAddrV4, UdpTx>,
    rx: Option<UdpSocketReader>,
}

#[cfg(not(feature = "unit-tests"))]
impl UdpSocket {
    pub fn bind<A: ToSocketAddrs>(stack: Arc<Mutex<NetworkStack>>,
                                  addr: A)
                                  -> io::Result<UdpSocket> {
        let mut socket_reader = UdpSocketReader::new();
        let socket_addr = {
            let mut stack = stack.lock().unwrap();
            try!(stack.udp_listen(addr, socket_reader.listener()))
        };
        Ok(UdpSocket {
            socket_addr: socket_addr,
            stack: stack,
            tx_cache: HashMap::new(),
            rx: Some(socket_reader),
        })
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.rx.as_ref().unwrap().recv_from(buf)
    }

    pub fn send_to<A: ToSocketAddrs>(&mut self, buf: &[u8], addr: A) -> io::Result<usize> {
        match try!(util::first_socket_addr(addr)) {
            SocketAddr::V4(dst) => {
                self.internal_send(buf, dst)
                    .map(|_| buf.len())
                    .map_err(|e| e.into())
            }
            SocketAddr::V6(_dst) => {
                Err(io::Error::new(io::ErrorKind::InvalidInput,
                                   "Rips does not support IPv6 yet".to_owned()))
            }
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.socket_addr)
    }

    pub fn try_clone(&self) -> io::Result<UdpSocket> {
        Ok(UdpSocket {
            socket_addr: self.socket_addr,
            stack: self.stack.clone(),
            tx_cache: HashMap::new(),
            rx: None,
        })
    }

    fn internal_send(&mut self, buf: &[u8], dst: SocketAddrV4) -> StackResult<()> {
        match self.internal_send_on_cached_tx(buf, dst) {
            Err(TxError::InvalidTx) => {
                let (dst_ip, dst_port) = (*dst.ip(), dst.port());
                let new_udp_tx = {
                    let mut stack = self.stack.lock().unwrap();
                    try!(stack.udp_tx(dst_ip, self.socket_addr.port(), dst_port))
                };
                self.tx_cache.insert(dst, new_udp_tx);
                self.internal_send(buf, dst)
            }
            result => result.map_err(StackError::TxError),
        }
    }

    fn internal_send_on_cached_tx(&mut self, buf: &[u8], dst: SocketAddrV4) -> TxResult {
        if buf.len() > ::std::u16::MAX as usize {
            return Err(TxError::TooLargePayload);
        }
        if let Some(udp_tx) = self.tx_cache.get_mut(&dst) {
            udp_tx.send(buf)
        } else {
            // No cached UdpTx is treated as an existing but outdated one
            Err(TxError::InvalidTx)
        }
    }
}
