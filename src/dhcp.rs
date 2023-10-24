//! In this file we manage the DHCP specific data types and parsing

use log::{error, info, warn};

use crate::types::{
    ClientIdentifier, DhcpOption, DhcpOptionList, MacAddr, MessageType, ParameterRequest,
};
use crate::UDP_BUFFER_SIZE;
use crate::{AddrPool, Error, Result};
use std::sync::{Arc, Mutex, MutexGuard};

/// A [Dhcp] represents a DHCP packet
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct Dhcp<'dhcp> {
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
    options: DhcpOptionList<'dhcp>,

    /// Required option that makes sense to store top level
    message_type: MessageType,
}

impl<'dhcp> Dhcp<'dhcp> {
    /// The "magic" of a DHCP Payload
    const MAGIC: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
    const MINIMUM_PAYLOAD_LENGTH: usize = 240;
    const OPTIONS_START: usize = 240;
    const OPTION_LEN_OFFSET: usize = 1;
    const REQUEST_OP_CODE: u8 = 1;
    const REPLY_OP_CODE: u8 = 2;
    const HW_TYPE_ETHERNET: u8 = 1;
    const HW_ADDRESS_LEN: u8 = 6;

    /// Convert &[u8] from a UDP Packet into a more rust friendly Dhcp struct
    pub fn parse(data: &[u8]) -> Result<Self> {
        let data_len = data.len();

        if data_len < Self::MINIMUM_PAYLOAD_LENGTH {
            return Err(Error::PayloadTooShort(data_len));
        }

        let dhcp_op_code = data[0];
        if dhcp_op_code != Self::REQUEST_OP_CODE {
            return Err(Error::NotADhcpRequest(dhcp_op_code));
        }

        if data[236..240] != Self::MAGIC {
            return Err(Error::DhcpMagicMissing);
        }

        let mut message_type = MessageType::Unset;
        let mut option_ptr = Self::OPTIONS_START;
        let mut options = DhcpOptionList::builder();
        loop {
            // The options pointer is out of bounds so we are done
            if option_ptr >= data_len {
                break;
            }

            // We will store the option length so we can increment
            let mut option_len = 0;

            let option_opcode: u8 = data[option_ptr];

            // Add the option to our array of options if we found one and
            // increment the counter
            match option_opcode {
                DhcpOption::PAD => _ = options.add(DhcpOption::Pad),
                DhcpOption::MESSAGE_TYPE => {
                    option_len = *data
                        .get(option_ptr + Self::OPTION_LEN_OFFSET)
                        .ok_or(Error::DhcpOptionLenOutOfBounds)?;

                    if option_len != DhcpOption::MESSAGE_TYPE_LEN {
                        return Err(Error::MessageTypeBadLen(option_len));
                    }

                    option_ptr += Self::OPTION_LEN_OFFSET + 1;

                    if let Some(msg_type) = data.get(option_ptr) {
                        message_type = (*msg_type).try_into()?;
                    };
                }
                DhcpOption::REQUESTED_IP_ADDR => {
                    option_len = *data
                        .get(option_ptr + Self::OPTION_LEN_OFFSET)
                        .ok_or(Error::DhcpOptionLenOutOfBounds)?;

                    if option_len != DhcpOption::IP_ADDR_LEN {
                        return Err(Error::InvalidIpAddrLen(option_len));
                    }

                    option_ptr += Self::OPTION_LEN_OFFSET + 1;

                    let ip_addr_bytes =
                        data.get(option_ptr..option_ptr + DhcpOption::IP_ADDR_LEN as usize);

                    if let Some(ip_addr_bytes) = ip_addr_bytes {
                        // We can unwap safetly here because we check above
                        let ip_addr = <[u8; 4]>::try_from(ip_addr_bytes).unwrap();
                        options.add(DhcpOption::RequestedIpAddr(ip_addr));
                    }
                }
                DhcpOption::DHCP_SERVER_IP_ADDR => {
                    option_len = *data
                        .get(option_ptr + Self::OPTION_LEN_OFFSET)
                        .ok_or(Error::DhcpOptionLenOutOfBounds)?;

                    if option_len != DhcpOption::IP_ADDR_LEN {
                        return Err(Error::InvalidIpAddrLen(option_len));
                    }

                    option_ptr += Self::OPTION_LEN_OFFSET + 1;

                    let ip_addr_bytes =
                        data.get(option_ptr..option_ptr + DhcpOption::IP_ADDR_LEN as usize);

                    if let Some(ip_addr_bytes) = ip_addr_bytes {
                        // We can unwap safetly here because we check above
                        let ip_addr = <[u8; 4]>::try_from(ip_addr_bytes).unwrap();
                        options.add(DhcpOption::DhcpServerIpAddr(ip_addr));
                    }
                }
                DhcpOption::MAX_MESSAGE_SIZE => {
                    option_len = *data
                        .get(option_ptr + Self::OPTION_LEN_OFFSET)
                        .ok_or(Error::DhcpOptionLenOutOfBounds)?;

                    if option_len != DhcpOption::MAX_MESSAGE_SIZE_LEN {
                        return Err(Error::MaxMessageSizeBadLen(option_len));
                    }

                    // Increment pointer to start of data
                    option_ptr += Self::OPTION_LEN_OFFSET + 1;

                    let max_msg_size = data
                        .get(option_ptr..option_ptr + DhcpOption::MAX_MESSAGE_SIZE_LEN as usize);

                    if let Some(max_msg_size) = max_msg_size {
                        let max_msg_size = u16::from_be_bytes(max_msg_size.try_into().unwrap());
                        options.add(DhcpOption::MaxMessageSize(max_msg_size));
                    }
                }
                DhcpOption::PARAMETER_REQUEST_LIST => {
                    option_len = *data
                        .get(option_ptr + Self::OPTION_LEN_OFFSET)
                        .ok_or(Error::DhcpOptionLenOutOfBounds)?;

                    if option_len < DhcpOption::MIN_PARAMETER_REQUEST_LEN {
                        return Err(Error::InvalidParameterRequestLen(option_len));
                    }
                    if option_len > DhcpOption::MAX_PARAMETER_REQUEST_LIST_LEN {
                        return Err(Error::InvalidParameterRequestLen(option_len));
                    }

                    // Increment pointer to start of data
                    option_ptr += Self::OPTION_LEN_OFFSET + 1;

                    let list = data.get(option_ptr..option_ptr + option_len as usize);

                    if let Some(list) = list {
                        let mut req_params = [None; DhcpOptionList::MAX_LEN as usize];

                        for (index, param) in list.iter().enumerate() {
                            let req_param = (*param).into();
                            req_params[index] = Some(req_param);
                        }
                        options.add(DhcpOption::ParameterRequestList(req_params));
                    }
                }
                DhcpOption::VENDOR_CLASS_ID => {
                    option_len = *data
                        .get(option_ptr + Self::OPTION_LEN_OFFSET)
                        .ok_or(Error::DhcpOptionLenOutOfBounds)?;

                    if option_len > DhcpOption::MAX_VENDOR_CLASS_ID_LEN {
                        return Err(Error::InvalidVendorClassIdentifierLen(option_len));
                    }

                    // Increment pointer to start of data
                    option_ptr += Self::OPTION_LEN_OFFSET + 1;

                    let option_raw = data.get(option_ptr..option_ptr + option_len as usize);

                    if let Some(option_raw) = option_raw {
                        let mut option = [0u8; DhcpOption::MAX_VENDOR_CLASS_ID_LEN as usize];
                        option[..option_len as usize]
                            .copy_from_slice(&option_raw[..option_len as usize]);

                        options.add(DhcpOption::VendorClassIndentifier(option));
                    }
                }
                DhcpOption::CLIENT_SYSTEM_ARCH => {
                    option_len = *data
                        .get(option_ptr + Self::OPTION_LEN_OFFSET)
                        .ok_or(Error::DhcpOptionLenOutOfBounds)?;

                    if option_len != DhcpOption::CLIENT_SYSTEM_ARCH_LEN {
                        return Err(Error::InvalidClientSystemArchLen(option_len));
                    }

                    // Increment pointer to start of data
                    option_ptr += Self::OPTION_LEN_OFFSET + 1;

                    let option_raw = data.get(option_ptr..option_ptr + option_len as usize);

                    if let Some(option_raw) = option_raw {
                        let mut option = [0u8; DhcpOption::CLIENT_SYSTEM_ARCH_LEN as usize];
                        option.copy_from_slice(&option_raw[..option_len as usize]);
                        options.add(DhcpOption::ClientSystemArch(option));
                    }
                }
                DhcpOption::CLIENT_NET_DEV_INTERFACE => {
                    option_len = *data
                        .get(option_ptr + Self::OPTION_LEN_OFFSET)
                        .ok_or(Error::DhcpOptionLenOutOfBounds)?;

                    if option_len != DhcpOption::CLIENT_NET_DEV_INTERFACE_LEN {
                        return Err(Error::InvalidClientNetworkDeviceInterfaceLen(option_len));
                    }

                    // Increment pointer to start of data
                    option_ptr += Self::OPTION_LEN_OFFSET + 1;

                    let option_raw = data.get(option_ptr..option_ptr + option_len as usize);

                    if let Some(option_raw) = option_raw {
                        let mut option = [0u8; DhcpOption::CLIENT_NET_DEV_INTERFACE_LEN as usize];
                        option.copy_from_slice(&option_raw[..option_len as usize]);
                        options.add(DhcpOption::ClientNetworkDeviceInterface(option));
                    }
                }
                DhcpOption::CLIENT_ID => {
                    option_len = *data
                        .get(option_ptr + Self::OPTION_LEN_OFFSET)
                        .ok_or(Error::DhcpOptionLenOutOfBounds)?;

                    option_ptr += Self::OPTION_LEN_OFFSET + 1;

                    let option_raw = &data[option_ptr..option_ptr + option_len as usize];

                    match ClientIdentifier::try_from(option_raw) {
                        Ok(client_id) => options.add(DhcpOption::ClientIdentifier(client_id)),
                        Err(err) => return Err(err),
                    };
                }
                DhcpOption::CLIENT_UID => {
                    option_len = *data
                        .get(option_ptr + Self::OPTION_LEN_OFFSET)
                        .ok_or(Error::DhcpOptionLenOutOfBounds)?;

                    if option_len < DhcpOption::MIN_CLIENT_UID_LEN {
                        return Err(Error::InvalidClientUidLen(option_len));
                    }
                    if option_len > DhcpOption::MAX_CLIENT_UID_LEN {
                        return Err(Error::InvalidClientUidLen(option_len));
                    }

                    // Increment pointer to start of data
                    option_ptr += Self::OPTION_LEN_OFFSET + 1;

                    let option_raw = data.get(option_ptr..option_ptr + option_len as usize);

                    if let Some(option_raw) = option_raw {
                        let mut option = [0u8; DhcpOption::MAX_CLIENT_UID_LEN as usize];
                        option.copy_from_slice(&option_raw[..option_len as usize]);
                        options.add(DhcpOption::ClientUid(option));
                    };
                }
                DhcpOption::END => _ = options.add(DhcpOption::End),
                // Catch options we have not defined
                option => {
                    option_len = *data
                        .get(option_ptr + Self::OPTION_LEN_OFFSET)
                        .ok_or(Error::DhcpOptionLenOutOfBounds)?;

                    // Increment pointer to start of data
                    option_ptr += Self::OPTION_LEN_OFFSET + 1;

                    warn!("Unknown DhcpOption Recieved: {option}");
                }
            };

            // Stop if we got an [DhcpOption::End]
            if option_opcode == DhcpOption::END {
                break;
            }
            // Increment counter
            option_ptr += option_len as usize;
        }

        if message_type == MessageType::Unset {
            return Err(Error::NoMessageDhcpTypeProvided);
        }

        Ok(Self {
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
            message_type,
        })
    }

    /// Construct a new Dhcp response given a request
    fn build_response(&self) -> Self {
        Self {
            op_code: Self::REPLY_OP_CODE,
            hw_addr_ty: Self::HW_TYPE_ETHERNET,
            hw_addr_len: Self::HW_ADDRESS_LEN,
            // NOT IMPLEMENTED
            hops: 0,
            transaction_id: self.transaction_id,
            // NOT IMPLEMENTED
            secs: [0, 0],
            flags: [0, 0],
            client_addr: [0, 0, 0, 0],
            // NOT IMPLEMENTED
            server_addr: [0, 0, 0, 0],
            next_server_addr: [0, 0, 0, 0],
            relay_addr: [0, 0, 0, 0],
            client_hw_addr: self.client_hw_addr,
            // NOT IMPLEMENTED
            server_hostname: [0u8; 64],
            // NOT IMPLMENTED
            file: [0u8; 128],
            options: DhcpOptionList::builder(),
            message_type: MessageType::Unset,
        }
    }

    fn insert_requested_options(&self, pool: &MutexGuard<AddrPool<'dhcp>>, res: &mut Self) {
        let insert_matching_options = |req_option: &ParameterRequest| {
            if let Some(opt) = pool.options().consume()[*req_option as usize] {
                _ = &res.options.add(opt);
            } else {
                warn!("Did not include option: {req_option:?}")
            }
        };

        if let Some(DhcpOption::ParameterRequestList(option_req_list)) =
            self.options.get(DhcpOption::PARAMETER_REQUEST_LIST)
        {
            option_req_list
                .iter()
                .flatten()
                .for_each(insert_matching_options);
        }
    }

    fn insert_server_addr(&self, pool: &MutexGuard<AddrPool<'dhcp>>, res: &mut Self) {
        if let Some(DhcpOption::DhcpServerIpAddr(addr)) =
            pool.options().get(DhcpOption::DHCP_SERVER_IP_ADDR)
        {
            res.server_addr = addr;
            res.options.add(DhcpOption::DhcpServerIpAddr(addr));
        }
    }

    fn insert_lease(&self, pool: &MutexGuard<AddrPool<'dhcp>>, res: &mut Self) {
        if let Some(DhcpOption::LeaseTime(lease)) = pool.options().get(DhcpOption::LEASE_TIME) {
            res.options.add(DhcpOption::LeaseTime(lease));
        }
    }

    /// Handler for a DHCP Discover
    fn offer(&self, pool: Arc<Mutex<AddrPool<'dhcp>>>) -> Self {
        let mut res = self.build_response();
        let mut pool = pool.lock().unwrap();

        res.client_addr = pool.request(&MacAddr::new(self.client_hw_addr)).octets();

        self.insert_requested_options(&pool, &mut res);
        self.insert_lease(&pool, &mut res);
        self.insert_server_addr(&pool, &mut res);

        drop(pool);

        // Specific Offer Options
        res.options
            .add(DhcpOption::MessageType(MessageType::Offer))
            .add(DhcpOption::End);
        res
    }

    #[inline(always)]
    fn ack(&self, res: &mut Self, pool: MutexGuard<AddrPool<'dhcp>>) {
        self.insert_requested_options(&pool, res);
        self.insert_server_addr(&pool, res);

        drop(pool);

        res.options
            .add(DhcpOption::MessageType(MessageType::Ack))
            .add(DhcpOption::End);
    }

    #[inline(always)]
    fn nack(&self, res: &mut Self) {
        res.options
            .add(DhcpOption::MessageType(MessageType::Nack))
            .add(DhcpOption::End);
    }

    fn verify(&self, pool: Arc<Mutex<AddrPool<'dhcp>>>) -> Dhcp {
        let mut res = self.build_response();
        let requested_ip = self.options.get(DhcpOption::REQUESTED_IP_ADDR);
        let client_mac: MacAddr = self.client_hw_addr.into();

        let pool = pool.lock().unwrap();

        // RENEWING | REBINDING
        let client_ip_set = self.client_addr != [0, 0, 0, 0];
        if client_ip_set && requested_ip.is_none() {
            res.client_addr = self.client_addr;
            self.ack(&mut res, pool);
            return res;
        }

        // SELECTING || INIT-REBOOT
        if let Some(DhcpOption::RequestedIpAddr(ip)) = requested_ip {
            if pool.verify_request(&client_mac, &ip.into()).is_some() {
                res.client_addr = ip;
                self.ack(&mut res, pool);
                return res;
            }
            warn!("Client requested IP not valid: {:?}", requested_ip);
        }

        // Fallthrough into nack
        self.nack(&mut res);
        error!(
            "Sending Nack XID: {:X?}, MAC: {:X?}",
            self.transaction_id, self.client_hw_addr
        );
        res
    }

    fn serialiase(&self, buffer: &mut [u8; UDP_BUFFER_SIZE]) -> usize {
        buffer[0] = self.op_code;
        buffer[1] = self.hw_addr_ty;
        buffer[2] = self.hw_addr_len;
        buffer[3] = self.hops;
        buffer[4..8].copy_from_slice(&self.transaction_id);
        buffer[10..12].copy_from_slice(&self.flags);
        buffer[16..20].copy_from_slice(&self.client_addr);
        buffer[20..24].copy_from_slice(&self.server_addr);
        buffer[28..34].copy_from_slice(&self.client_hw_addr);
        buffer[236..240].copy_from_slice(&Dhcp::MAGIC);

        self.set_options(buffer)
    }

    fn set_options(&self, buffer: &mut [u8; UDP_BUFFER_SIZE]) -> usize {
        // Start at 240 (After the magic bytes)
        let mut option_ptr = 240;
        // For every option we want
        for opt in self.options.consume() {
            if opt.is_none() {
                continue;
            }
            // Take the length so we can dynamically push on our option
            let len = opt.unwrap().serialise(&mut buffer[option_ptr..]);
            // Increment the UDP data len
            option_ptr += len;
        }
        // Final Len of the UDP packet
        option_ptr
    }

    /// State machine to decide what to do with packet
    pub fn handle(
        &self,
        pool: Arc<Mutex<AddrPool<'dhcp>>>,
        buffer: &mut [u8; UDP_BUFFER_SIZE],
    ) -> usize {
        info!("Recieved {:?}", self.message_type);
        match self.message_type {
            MessageType::Discover => {
                let offer = self.offer(pool);
                info!("Sending IP Offer: {:?}", offer.client_addr);
                offer.serialiase(buffer)
            }
            MessageType::Request => self.verify(pool).serialiase(buffer),
            _ => {
                todo!("{:?}", self.message_type)
            }
        }
    }
}
