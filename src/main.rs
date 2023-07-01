//! # DHC3PO
//! The DHCP server for star wars fans!

use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::thread;

mod dhcp;
mod error;
mod state;
mod types;

use dhcp::Dhcp;
use error::{Error, Result};
use state::AddressPool;

/// Port we listen for incomming DHCP requests, 67 is standard
const SERVER_PORT: u16 = 67;
/// Port we listen for incomming DHCP requests, 67 is standard
const CLIENT_PORT: u16 = 68;
/// Address we listen on 0.0.0.0 means all interfaces
const BIND_ADDRESS: &str = "0.0.0.0";
/// Address we listen on 0.0.0.0 means all interfaces
const BROADCAST_ADDRESS: &str = "255.255.255.255";
/// Any bytes over 512 will be discarded
const UDP_BUFFER_SIZE: usize = 512;

/// Our main logic, bind to our [BIND_ADDRESS]:[SERVER_PORT] and handle requests
fn main() -> ! {
    // Get a socket from the OS
    let socket = UdpSocket::bind((BIND_ADDRESS, SERVER_PORT))
        .map_err(Error::CannotBindToAddress)
        .unwrap();
    socket.set_broadcast(true).unwrap();

    // Get an IP Range to Allocate to and share between threads
    let dhcp_range = Arc::new(Mutex::new(AddressPool::new(
        [192, 168, 1, 0],
        [255, 255, 255, 0],
    )));

    loop {
        let buffer = &mut [0u8; UDP_BUFFER_SIZE];

        match socket.recv_from(buffer) {
            Ok((data_len, _)) => {
                thread::scope(|_| handle_request(&socket, dhcp_range.clone(), &buffer[..data_len]));
            }
            Err(ref error) => handle_error(error),
        };
    }
}

/// If the recv call fails, handle and log the errors
fn handle_error(error: &std::io::Error) {
    match error.raw_os_error() {
        Some(error::RECV_DATA_LARGER_THAN_BUFFER) => dbg!(error),
        Some(error) => todo!("{}", error),
        None => todo!("{}", error),
    };
}

/// The entry point to our [Dhcp] logic
fn handle_request(socket: &UdpSocket, pool: Arc<Mutex<AddressPool>>, data: &[u8]) {
    dbg!(socket);

    let mut response_buffer = [0u8; UDP_BUFFER_SIZE];
    let len = Dhcp::parse(data).unwrap().handle(pool, &mut response_buffer);
    socket
        .send_to(&response_buffer[..len], (BROADCAST_ADDRESS, CLIENT_PORT))
        .unwrap();
}

