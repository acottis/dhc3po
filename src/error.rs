//! Our custom error handler that we use to wrap errors and give them a more
//! readable error message

pub const RECV_DATA_LARGER_THAN_BUFFER: i32 = 10040;

#[derive(Debug)]
pub enum Error {
    /// Failed to bind to the requested [super::BIND_ADDRESS]:[super::SERVER_PORT]
    CannotBindToAddress(std::io::Error),

    /// Too short to be a DHCP packet
    PayloadTooShort(usize),

    /// As a DHCP server we only care about requests
    NotADhcpRequest(u8),

    /// Missing the DHCP magic bytes at 236..240
    DhcpMagicMissing,

    /// The Dhcp Option is not handled
    UnhandledDhcpOption(u8),

    /// Invalid value in the op field
    InvalidDhcpOpCode(u8),

    /// A Dhcp message must contain a message type
    NoMessageDhcpTypeProvided,

    /// The Dhcp Option is not handled
    InvalidDhcpOptionMessageType(u8),

    /// DHCP Option Length index is out of bounds
    DhcpOptionLenOutOfBounds,

    /// The message type is not 1 byte
    MessageTypeBadLen(u8),

    /// The max message size is not 2 bytes
    MaxMessageSizeBadLen(u8),

    /// The minimum allowed is 1 byte
    InvalidParameterRequestLen(u8),

    /// We set a limit in [crate::dhcp::MAX_PARAMETER_REQUEST_LIST_LEN]
    UnsupportedRequestedParameters(u8),

    /// Limits set in [crate::dhcp::DhcpOption::MIN_CLIENT_UID_LEN] and
    /// [crate::dhcp::DhcpOption::MAX_CLIENT_UID_LEN]
    InvalidClientUidLen(u8),

    /// Expected to be 3 bytes
    InvalidClientNetworkDeviceInterfaceLen(u8),

    /// Expected to be 2 bytes
    InvalidClientSystemArchLen(u8),

    /// We only support Max Address Len's
    UnsupportedClientIdentifierLen(u8),

    /// We only support ethernet 0x1
    UnsupportedClientIdHwType(u8),

    /// Expected to be 32 bytes
    InvalidVendorClassIdentifierLen(u8),
}

/// Our custom Error type, we wrap all library errors inside our [Error]
pub type Result<T> = std::result::Result<T, self::Error>;
