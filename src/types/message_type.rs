use crate::Error;

/// Value message types for [DhcpOption::MessageType] (53)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nack = 6,
    Release = 7,
    Inform = 8,
    Unset = 255,
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
