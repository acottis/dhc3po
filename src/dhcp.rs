//! In this file we manage the DHCP specific data types and parsing

use crate::{Result, Error};

/// A [Dhcp] represents a DHCP packet
#[derive(Debug)]
pub struct Dhcp{
    /// op - Operate Code of the message
    op_code: u8,

    /// htype - What type of hardware address, i.e. MAC
    hw_addr_ty: u8,

    /// hlen - hardware address length
    hw_addr_len: u8,

    /// hops - how many network hops
    hops: u8,

    /// xid - The unique ID of a specific transaction between client and server
    transaction_id: [u8; 4],

    /// secs - Filled in by client, seconds elapsed since client began address
    /// acquisition or renewal process.
    secs: [u8; 2],

    /// flags
	flags: [u8; 2],

    /// ciaddr - Address of requestee
	client_addr: [u8; 4],

    /// yiaddr - The DHCP server address
	server_addr: [u8; 4],

    /// siaddr - The next server to ask about future steps
	next_server_addr: [u8; 4],

	/// giaddr - Relay agent IP address, used in booting via relay agent.
    relay_addr: [u8; 4],

    /// chaddr - Client hardware address (We will only handle MAC)
	client_hw_addr: [u8; 6],

    // sname - Optional server host name, null terminated string.
	server_hostname: [u8; 64],

    /// file - Boot file name, null terminated string; "generic" name or null
    /// in DHCPDISCOVER, fully qualified directory-path name in DHCPOFFER.
	file: [u8; 128],

    /// options - The variable length data after the magic
    options: [Option<DhcpOption>; Self::MAX_DHCP_OPTIONS_LEN]
}

impl Dhcp {
    /// The "magic" of a DHCP Payload
    const MAGIC: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
    const MINIMUM_PAYLOAD_LENGTH: usize = 240;
    const OPTIONS_START: usize = 240;
    const OPTION_LEN_OFFSET: usize = 1;
    const MAX_DHCP_OPTIONS_LEN: usize = 20;

    /// Convert &[u8] from a UDP Packet into a more rust friendly Dhcp struct
    pub fn parse(data: &[u8]) -> Result<Self> {
        let data_len = data.len();

        if data_len < Self::MINIMUM_PAYLOAD_LENGTH {
            return Err(Error::PayloadTooShort(data_len))
        }

        if data[236..240] != Self::MAGIC {
            return Err(Error::DhcpMagicMissing)
        }

        let mut opt_ptr = Self::OPTIONS_START;
        let mut options = [None; Self::MAX_DHCP_OPTIONS_LEN];
        let mut options_counter = 0;
        loop {
            // The options pointer is out of bounds so we are done
            if opt_ptr >= data_len { break }
            if options_counter >= Self::MAX_DHCP_OPTIONS_LEN { break }

            let mut option_len = 0;
            let dhcp_option_opcode: u8 = data[opt_ptr];

            let dhcp_option = match dhcp_option_opcode {
                DhcpOption::PAD => {
                    Some(DhcpOption::Pad)
                }
                DhcpOption::MESSAGE_TYPE => {
                    option_len = data[opt_ptr + Self::OPTION_LEN_OFFSET];

                    if option_len != DhcpOption::MESSAGE_TYPE_LEN {
                        return Err(Error::MessageTypeBadLen(option_len))
                    }

                    opt_ptr += Self::OPTION_LEN_OFFSET + 1;

                    if let Some(msg_type) = data.get(opt_ptr){
                        let msg_type: MessageType = (*msg_type).try_into()?;
                        Some(DhcpOption::MessageType(msg_type))
                    }else{
                        None
                    }
                }
                DhcpOption::MAX_MESSAGE_SIZE => {
                    option_len = data[opt_ptr + Self::OPTION_LEN_OFFSET];

                    if option_len != DhcpOption::MAX_MESSAGE_SIZE_LEN {
                        return Err(Error::MaxMessageSizeBadLen(option_len))
                    }

                    // Increment pointer to start of data
                    opt_ptr += Self::OPTION_LEN_OFFSET + 1;

                    let max_msg_size = data.get(
                        opt_ptr .. opt_ptr + DhcpOption::MAX_MESSAGE_SIZE_LEN as usize
                    );
                    if let Some(max_msg_size) = max_msg_size {
                        let max_msg_size = u16::from_be_bytes(
                            max_msg_size.try_into().unwrap()
                        );
                        Some(DhcpOption::MaxMessageSize(max_msg_size))
                    }else{
                        None
                    }
                }
                DhcpOption::PARAMETER_REQUEST_LIST => {
                    option_len = data[opt_ptr + Self::OPTION_LEN_OFFSET];

                    if option_len < DhcpOption::MIN_PARAMETER_REQUEST_LEN {
                        return Err(Error::InvalidParameterRequestLen(option_len))
                    }
                    if option_len > DhcpOption::MAX_PARAMETER_REQUEST_LIST_LEN {
                        return Err(Error::UnsupportedRequestedParameters(option_len))
                    }

                    // Increment pointer to start of data
                    opt_ptr += Self::OPTION_LEN_OFFSET + 1;

                    let list = data.get(
                        opt_ptr .. opt_ptr + option_len as usize
                    );

                    if let Some(list) = list {
                        let mut req_params: [Option<ParameterRequest>; DhcpOption::MAX_PARAMETER_REQUEST_LIST_LEN as usize]
                            = [None; DhcpOption::MAX_PARAMETER_REQUEST_LIST_LEN as usize];

                        for (index, param) in list.iter().enumerate(){
                            let req_param = (*param).into();
                            req_params[index] = Some(req_param);
                        }
                        Some(DhcpOption::ParameterRequestList(req_params))
                    }else{
                        None
                    }
                }
                DhcpOption::VENDOR_CLASS_IDENTIFIER => {
                    option_len = data[opt_ptr + Self::OPTION_LEN_OFFSET];

                    if option_len != DhcpOption::VENDOR_CLASS_IDENTIFIER_LEN {
                        return Err(Error::InvalidVendorClassIdentifierLen(option_len))
                    }

                    // Increment pointer to start of data
                    opt_ptr += Self::OPTION_LEN_OFFSET + 1;

                    let option_raw = data.get(
                        opt_ptr .. opt_ptr + option_len as usize
                    );

                    if let Some(option_raw) = option_raw{
                        let mut option = [0u8; DhcpOption::VENDOR_CLASS_IDENTIFIER_LEN as usize];
                        option.copy_from_slice(&option_raw[.. option_len as usize]);
                        Some(DhcpOption::VendorClassIndentifier(option))
                    }else{
                        None
                    }
                }
                DhcpOption::CLIENT_SYSTEM_ARCH => {
                    option_len = data[opt_ptr + Self::OPTION_LEN_OFFSET];

                    if option_len != DhcpOption::CLIENT_SYSTEM_ARCH_LEN {
                        return Err(Error::InvalidClientSystemArchLen(option_len))
                    }

                    // Increment pointer to start of data
                    opt_ptr += Self::OPTION_LEN_OFFSET + 1;

                    let option_raw = data.get(
                        opt_ptr .. opt_ptr + option_len as usize
                    );

                    if let Some(option_raw) = option_raw{
                        let mut option = [0u8; DhcpOption::CLIENT_SYSTEM_ARCH_LEN as usize];
                        option.copy_from_slice(&option_raw[.. option_len as usize]);
                        Some(DhcpOption::ClientSystemArch(option))
                    }else{
                        None
                    }
                }
                DhcpOption::CLIENT_NETWORK_DEVICE_INTERFACE => {
                    option_len = data[opt_ptr + Self::OPTION_LEN_OFFSET];

                    if option_len != DhcpOption::CLIENT_NETWORK_DEVICE_INTERFACE_LEN {
                        return Err(Error::InvalidClientNetworkDeviceInterfaceLen(option_len))
                    }

                    // Increment pointer to start of data
                    opt_ptr += Self::OPTION_LEN_OFFSET + 1;

                    let option_raw = data.get(
                        opt_ptr .. opt_ptr + option_len as usize
                    );

                    if let Some(option_raw) = option_raw{
                        let mut option = [0u8; DhcpOption::CLIENT_NETWORK_DEVICE_INTERFACE_LEN as usize];
                        option.copy_from_slice(&option_raw[.. option_len as usize]);
                        Some(DhcpOption::ClientNetworkDeviceInterface(option))
                    }else{
                        None
                    }
                }
                DhcpOption::CLIENT_IDENTIFIER => {
                    option_len = data[opt_ptr + Self::OPTION_LEN_OFFSET];

                    if option_len < DhcpOption::MIN_CLIENT_IDENTIFIER_LEN {
                        return Err(Error::InvalidClientIdentifierLen(option_len))
                    }
                    if option_len > DhcpOption::MAX_CLIENT_IDENTIFIER_LEN {
                        return Err(Error::InvalidClientIdentifierLen(option_len))
                    }

                    // Increment pointer to start of data
                    opt_ptr += Self::OPTION_LEN_OFFSET + 1;

                    let option_raw = data.get(
                        opt_ptr .. opt_ptr + option_len as usize
                    );

                    if let Some(option_raw) = option_raw{
                        let mut option = [0u8; DhcpOption::MAX_CLIENT_IDENTIFIER_LEN as usize];
                        option.copy_from_slice(&option_raw[.. option_len as usize]);
                        Some(DhcpOption::ClientIdentifier(option))
                    }else{
                        None
                    }
                }
                DhcpOption::END => {
                    Some(DhcpOption::End)
                }
                unknown => {
                    println!("Found Option {:X} with length {:X}", unknown, data[opt_ptr+1]);
                    option_len = data[opt_ptr + Self::OPTION_LEN_OFFSET];
                    opt_ptr += 2;
                    None
                }
            };
            // Add the option to our array of options if we found one and
            // increment the counter
            options[options_counter] = dhcp_option;
            // Stop if we got an [DhcpOption::End]
            if dhcp_option_opcode == DhcpOption::END{ break }
            // Increment counter past opcode
            options_counter += 1;
            // Increment counter
            opt_ptr += option_len as usize;

        }

        Ok(Self{
            op_code: data[0],
            hw_addr_ty: data[1],
            hw_addr_len: data[2],
            hops: data[3],
            transaction_id: data[4..8].try_into().unwrap(),
            secs: data[8..10].try_into().unwrap(),
            flags: data[10..12].try_into().unwrap(),
            client_addr: data[12..16].try_into().unwrap(),
            server_addr: data[16..20].try_into().unwrap(),
            next_server_addr: data[20..24].try_into().unwrap(),
            relay_addr: data[24..28].try_into().unwrap(),
            client_hw_addr: data[28..34].try_into().unwrap(),
            server_hostname: data[44..108].try_into().unwrap(),
            file: data[108..236].try_into().unwrap(),
            options,
        })
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum DhcpOption {
    /// 0
    Pad,

    /// 53
    MessageType(MessageType),

    /// 55
    ParameterRequestList([Option<ParameterRequest>; Self::MAX_PARAMETER_REQUEST_LIST_LEN as usize]),

    /// 57
    MaxMessageSize(u16),

    /// 60
    VendorClassIndentifier([u8; Self::VENDOR_CLASS_IDENTIFIER_LEN as usize]),

    /// 93
    ClientSystemArch([u8; 2]),

    /// 94
    ClientNetworkDeviceInterface([u8; Self::CLIENT_NETWORK_DEVICE_INTERFACE_LEN as usize]),

    /// 97
    ClientIdentifier([u8; Self::MAX_CLIENT_IDENTIFIER_LEN as usize]),

    /// 255
    End,
}

impl DhcpOption {
    const PAD: u8 = 0;
    const MESSAGE_TYPE: u8 = 53;
    const PARAMETER_REQUEST_LIST: u8 = 55;
    const MAX_MESSAGE_SIZE: u8 = 57;
    const VENDOR_CLASS_IDENTIFIER: u8 = 60;
    const CLIENT_SYSTEM_ARCH: u8 = 93;
    const CLIENT_NETWORK_DEVICE_INTERFACE: u8 = 94;
    const CLIENT_IDENTIFIER: u8 = 97;
    const END: u8 = 255;

    // Expected values
    const MAX_PARAMETER_REQUEST_LIST_LEN: u8 = 40;
    const MAX_CLIENT_IDENTIFIER_LEN: u8 = 17;
    const MIN_CLIENT_IDENTIFIER_LEN: u8 = 2;
    /// Expected length of [DhcpOption::MaxMessageSize]
    const MAX_MESSAGE_SIZE_LEN: u8 = 2;
    const MESSAGE_TYPE_LEN: u8 = 1;
    const MIN_PARAMETER_REQUEST_LEN: u8 = 1;
    const CLIENT_NETWORK_DEVICE_INTERFACE_LEN: u8 = 3;
    const CLIENT_SYSTEM_ARCH_LEN: u8 = 2;
    const VENDOR_CLASS_IDENTIFIER_LEN: u8 = 32;
}

#[allow(unused)]
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum ParameterRequest {
    SubnetMask                      = 1,
    TimeOffset                      = 2,
    Router                          = 3,
    TimeServer                      = 4,
    NameServer                      = 5,
    DomainNameServer                = 6,
    HostName                        = 12,
    BootFileSize                    = 13,
    DomainName                      = 15,
    RootPath                        = 17,
    ExtensionsPath                  = 18,
    MaxDatagramReassmblySize        = 22,
    DefaultIpTtl                    = 23,
    BroadcastAddress                = 28,
    PerformRouterDiscover           = 31,
    StaticRoute                     = 33,
    NetworkInformationServiceDomain = 40,
    NetworkInformationServiceServers= 41,
    NtpServers                      = 42,
    VendorSpecificInfo              = 43,
    NetBiosNameServer               = 44,
    NetBiosNodeType                 = 46,
    NetBiosScope                    = 47,
    RequestedIpAddress              = 50,
    IpAddressLease                  = 51,
    DhcpServerIndentifier           = 54,
    RenewalTimeValue                = 58,
    RebindingTimeValue              = 59,
    VendorClassIndentifier          = 60,
    TftpServerName                  = 66,
    BootfileName                    = 67,
    UUIDBasedClientIdentifier       = 97,
    DomainSearch                    = 119,
    ClasslessStaticRoute            = 121,
    DocsisFullSecurityServerIp      = 128,
    PxeUndefined1                   = 129,
    PxeUndefined2                   = 130,
    PxeUndefined3                   = 131,
    PxeUndefined4                   = 132,
    PxeUndefined5                   = 133,
    PxeUndefined6                   = 134,
    PxeUndefined7                   = 135,
    ClasslessStaticRouteMicrosoft   = 249,
    ProxyAutodiscovery              = 252,
}

impl From<u8> for ParameterRequest{
    fn from(value: u8) -> Self {
        match value {
            1 => Self::SubnetMask,
            2 => Self::TimeOffset,
            3 => Self::Router,
            4 => Self::TimeServer,
            5 => Self::NameServer,
            6 => Self::DomainNameServer,
            12 => Self::HostName,
            13 => Self::BootFileSize,
            15 => Self::DomainName,
            17 => Self::RootPath,
            18 => Self::ExtensionsPath,
            22 => Self::MaxDatagramReassmblySize,
            23 => Self::DefaultIpTtl,
            28 => Self::BroadcastAddress,
            31 => Self::PerformRouterDiscover,
            33 => Self::StaticRoute,
            40 => Self::NetworkInformationServiceDomain,
            41 => Self::NetworkInformationServiceServers,
            42 => Self::NtpServers,
            43 => Self::VendorSpecificInfo,
            44 => Self::NetBiosNameServer,
            46 => Self::NetBiosNodeType,
            47 => Self::NetBiosScope,
            50 => Self::RequestedIpAddress,
            51 => Self::IpAddressLease,
            54 => Self::DhcpServerIndentifier,
            58 => Self::RenewalTimeValue,
            59 => Self::RebindingTimeValue,
            60 => Self::VendorClassIndentifier,
            66 => Self::TftpServerName,
            67 => Self::BootfileName,
            97 => Self::UUIDBasedClientIdentifier,
            119 => Self::DomainSearch,
            121 => Self::ClasslessStaticRoute,
            128 => Self::DocsisFullSecurityServerIp,
            129 => Self::PxeUndefined1,
            130 => Self::PxeUndefined2,
            131 => Self::PxeUndefined3,
            132 => Self::PxeUndefined4,
            133 => Self::PxeUndefined5,
            134 => Self::PxeUndefined6,
            135 => Self::PxeUndefined7,
            249 => Self::ClasslessStaticRouteMicrosoft,
            252 => Self::ProxyAutodiscovery,
            unhandled => {
                todo!("RequestedParameter currently unhandled {}", unhandled);
            },
        }
    }
}

/// Value message types for [DhcpOption::MessageType] (53)
#[derive(Debug, Clone, Copy)]
pub enum MessageType {
	Discover = 1,
	Offer = 2,
	Request = 3,
	Decline = 4,
	Ack = 5,
	Nack = 6,
	Release = 7,
	Inform = 8,
}

impl TryFrom<u8> for MessageType {
	type Error = Error;

	fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
		match value {
			1 => Ok(Self::Discover),
			2 => Ok(Self::Offer),
			3 => Ok(Self::Request),
			4 => Ok(Self::Decline),
			5 => Ok(Self::Ack),
			6 => Ok(Self::Nack),
			7 => Ok(Self::Release),
			8 => Ok(Self::Inform),
			value => Err(Error::InvalidDhcpOptionMessageType(value)),
		}
	}
}