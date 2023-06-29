//! Our custom error handler that we use to wrap errors and give them a more
//! readable error message

pub const RECV_DATA_LARGER_THAN_BUFFER: i32 = 10040;

#[derive(Debug)]
pub enum Error{
    /// Failed to bind to the requested [super::BIND_ADDRESS]:[super::SERVER_PORT]
    CannotBindToAddress(std::io::Error),

    /// Too short to be a DHCP packet
    PayloadTooShort(usize),

    /// Missing the DHCP magic bytes at 236..240
    DhcpMagicMissing,

    /// The Dhcp Option is not handled
    UnhandledDhcpOption(u8),

    /// The Dhcp Option is not handled
    InvalidDhcpOptionMessageType(u8),

    /// The message type is not 1 byte
    MessageTypeBadLen(u8),

    /// The max message size is not 2 bytes
    MaxMessageSizeBadLen(u8),

    /// The minimum allowed is 1 byte
    InvalidParameterRequestLen(u8),

    /// We set a limit in [crate::dhcp::MAX_PARAMETER_REQUEST_LIST_LEN]
    UnsupportedRequestedParameters(u8),

    /// We set limits in [crate::dhcp::DhcpOption::MIN_CLIENT_IDENTIFIER_LEN] and
    /// [crate::dhcp::DhcpOption::MAX_CLIENT_IDENTIFIER_LEN]
    InvalidClientIdentifierLen(u8),

    /// Expected to be 3 bytes
    InvalidClientNetworkDeviceInterfaceLen(u8),

    /// Expected to be 2 bytes
    InvalidClientSystemArchLen(u8),

    /// Expected to be 32 bytes
    InvalidVendorClassIdentifierLen(u8),
}

/// Our custom Error type, we wrap all library errors inside our [Error]
pub type Result<T> = std::result::Result<T, self::Error>;