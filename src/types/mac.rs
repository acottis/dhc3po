//! Deals with mac addresses

#[derive(Debug, Clone, Copy)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub const LEN: usize = 6;

    pub fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }
}
