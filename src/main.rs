//! # DHC3PO
//! The DHCP server for star wars fans!

use std::thread;
use std::net::{SocketAddr, UdpSocket};

mod error;
use error::{Result, Error};
mod dhcp;
use dhcp::Dhcp;

/// Port we listen for incomming DHCP requests, 67 is standard
const SERVER_PORT: u16 = 67;
/// Address we listen on 0.0.0.0 means all interfaces
const BIND_ADDRESS: &'static str = "0.0.0.0";
/// Any bytes over 512 will be discarded
const UDP_BUFFER_SIZE: usize = 512;

/// Our main logic, bind to our [BIND_ADDRESS]:[SERVER_PORT] and handle requests
fn main() -> ! {
    // Get a socket from the OS
    let socket = UdpSocket::bind((BIND_ADDRESS, SERVER_PORT))
        .map_err(Error::CannotBindToAddress).unwrap();

    loop {
        let buffer = &mut [0u8; UDP_BUFFER_SIZE];

        match socket.recv_from(buffer) {
            Ok((data_len, client_address)) => {
                spawn_thread(client_address, buffer, data_len)
            }
            Err(ref error) => {
                handle_error(error)
            }
        };
    }
}

/// Takes the incomming data and length and spawns a worker thread to handle
/// the request
fn spawn_thread(client_address: SocketAddr, buffer: &[u8], data_len: usize){
    let local_buffer: [u8; UDP_BUFFER_SIZE] = buffer.try_into().unwrap();

    thread::spawn(move ||
        handle(client_address, &local_buffer[.. data_len])
    );
}

/// If the recv call fails, handle and log the errors
fn handle_error(error: &std::io::Error) {
    match error.raw_os_error() {
        Some(error::RECV_DATA_LARGER_THAN_BUFFER) => dbg!(error),
        Some(error) => todo!("{}", error),
        None => todo!("{}", error)
    };
}

/// The entry point to our [Dhcp] logic
fn handle(client_address: SocketAddr, data: &[u8]) {
    println!("{}, {:X?}", client_address, data);
    let dhcp_request = Dhcp::parse(data);
    println!("{:?}", dhcp_request);
}


