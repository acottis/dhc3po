use super::{MessageType, ParameterRequest, ClientIdentifier};

#[derive(Debug, Clone, Copy)]
#[repr(u8)]

pub enum DhcpOption<'option> {
    /// 0
    Pad,

    /// 1
    SubnetMask([u8; 4]),

    /// 3
    Router([u8; 4]),

    /// 6
    DomainNameServer([u8; 4]),

    /// 12
    HostName(&'option str),

    /// 12
    DomainName(&'option str),

    /// 12
    BroadcastAddress([u8; 4]),

    /// 51
    LeaseTime(u32),

    /// 53
    MessageType(MessageType),

    /// 54
    ServerIndentifier([u8; 4]),

    /// 55
    ParameterRequestList(
        [Option<ParameterRequest>; DhcpOption::MAX_PARAMETER_REQUEST_LIST_LEN as usize],
    ),

    /// 57
    MaxMessageSize(u16),

    /// 60
    VendorClassIndentifier([u8; DhcpOption::MAX_VENDOR_CLASS_ID_LEN as usize]),

    /// 61
    ClientIdentifier(ClientIdentifier),

    /// 93
    ClientSystemArch([u8; 2]),

    /// 94
    ClientNetworkDeviceInterface([u8; DhcpOption::CLIENT_NETWORK_DEVICE_INTERFACE_LEN as usize]),

    /// 97
    ClientUid([u8; DhcpOption::MAX_CLIENT_UID_LEN as usize]),

    /// 255
    End,
}

impl<'option> DhcpOption<'option> {
    pub const PAD: u8 = 0;
    pub const LEASE_TIME: u8 = 51;
    pub const MESSAGE_TYPE: u8 = 53;
    pub const PARAMETER_REQUEST_LIST: u8 = 55;
    pub const MAX_MESSAGE_SIZE: u8 = 57;
    pub const VENDOR_CLASS_ID: u8 = 60;
    pub const CLIENT_ID: u8 = 61;
    pub const CLIENT_SYSTEM_ARCH: u8 = 93;
    pub const CLIENT_NETWORK_DEVICE_INTERFACE: u8 = 94;
    pub const CLIENT_UID: u8 = 97;
    pub const END: u8 = 255;

    // Expected values
    pub const MAX_PARAMETER_REQUEST_LIST_LEN: u8 = 40;
    pub const MAX_CLIENT_UID_LEN: u8 = 17;
    pub const MIN_CLIENT_UID_LEN: u8 = 2;
    pub const MAX_MESSAGE_SIZE_LEN: u8 = 2;
    pub const MESSAGE_TYPE_LEN: u8 = 1;
    pub const MIN_PARAMETER_REQUEST_LEN: u8 = 1;
    pub const CLIENT_NETWORK_DEVICE_INTERFACE_LEN: u8 = 3;
    pub const CLIENT_SYSTEM_ARCH_LEN: u8 = 2;
    pub const MAX_VENDOR_CLASS_ID_LEN: u8 = 32;

    pub fn opcode(&self) -> u8 {
        match self {
            Self::Pad => 0,
            Self::SubnetMask(_) => 1,
            Self::Router(_) => 3,
            Self::DomainNameServer(_) => 6,
            Self::HostName(_) => 12,
            Self::DomainName(_) => 15,
            Self::BroadcastAddress(_) => 28,
            Self::LeaseTime(_) => 51,
            Self::MessageType(_) => 53,
            Self::ServerIndentifier(_) => 54,
            Self::ParameterRequestList(_) => 55,
            Self::MaxMessageSize(_) => 57,
            Self::VendorClassIndentifier(_) => 60,
            Self::ClientIdentifier(_) => 61,
            Self::ClientSystemArch(_) => 93,
            Self::ClientNetworkDeviceInterface(_) => 94,
            Self::ClientUid(_) => 97,
            Self::End => 255,
        }
    }

    pub fn serialise(&self, buffer: &mut [u8]) -> usize {
        buffer[0] = self.opcode();
        match self {
            Self::SubnetMask(address) => {
                let len: u8 = 6;
                buffer[1] = len - 2;
                buffer[2..6].copy_from_slice(address);
                len as usize
            }
            Self::Router(address) => {
                let len: u8 = 6;
                buffer[1] = len - 2;
                buffer[2..6].copy_from_slice(address);
                len as usize
            }
            Self::HostName(name) => {
                let len = name.len() + 2;
                buffer[1] = (len - 2) as u8;
                buffer[2..len].copy_from_slice(name.as_bytes());
                len
            }
            Self::DomainName(name) => {
                let len = name.len() + 2;
                buffer[1] = (len - 2) as u8;
                buffer[2..len].copy_from_slice(name.as_bytes());
                len
            }
            Self::BroadcastAddress(address) => {
                let len: u8 = 6;
                buffer[1] = len - 2;
                buffer[2..6].copy_from_slice(address);
                len as usize
            }
            Self::DomainNameServer(address) => {
                let len: u8 = 6;
                buffer[1] = len - 2;
                buffer[2..6].copy_from_slice(address);
                len as usize
            }
            Self::MessageType(message) => {
                let len: u8 = 3;
                buffer[1] = len - 2;
                buffer[2] = *message as u8;
                len as usize
            }
            Self::ServerIndentifier(address) => {
                let len: u8 = 6;
                buffer[1] = len - 2;
                buffer[2..6].copy_from_slice(address);
                len as usize
            }
            Self::LeaseTime(time) => {
                let len: u8 = 6;
                buffer[1] = len - 2;
                buffer[2] = (time >> 24) as u8;
                buffer[3] = (time >> 16) as u8;
                buffer[4] = (time >> 8) as u8;
                buffer[5] = *time as u8;
                len as usize
            }
            Self::End => 1,
            option => todo!("We dont yet serialise DHCP Option {option:?}"),
        }
    }
}
