use super::MacAddr;
use crate::Error;

#[derive(Debug, Copy, Clone)]
pub struct ClientIdentifier {
    hw_type: u8,
    id: MacAddr,
}

impl ClientIdentifier {
    pub const ETHERNET: u8 = 0x1;
    pub const LEN: u8 = 7;
}

impl TryFrom<&[u8]> for ClientIdentifier {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let hw_type = *value.first().unwrap();
        if hw_type != Self::ETHERNET {
            return Err(Error::UnsupportedClientIdHwType(hw_type));
        }
        let mac_bytes = value[1..].get(..MacAddr::LEN).unwrap();
        let mut mac_addr: [u8; 6] = [0u8; 6];
        mac_addr.copy_from_slice(mac_bytes);

        Ok(Self {
            hw_type,
            id: MacAddr::new(mac_addr),
        })
    }
}
