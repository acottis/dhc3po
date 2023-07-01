//! This is where we delcare our structs and logic for storage of IP Addresses
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

type DhcpRange = BTreeMap<Ipv4Addr, Option<Address>>;

#[derive(Debug)]
pub struct Address {
    hw_address: [u8; 6],
}

impl Address {
    fn new(hw_address: [u8; 6]) -> Self {
        Self { hw_address }
    }
}

#[derive(Debug)]
pub struct AddressPool {
    subnet: [u8; 4],
    mask: [u8; 4],
    pool: DhcpRange,
}

impl AddressPool {
    pub fn new(subnet: [u8; 4], mask: [u8; 4]) -> Self {
        Self {
            subnet,
            mask,
            pool: Self::create_pool(subnet, mask),
        }
    }

    pub fn update(&mut self, ip_addr: [u8; 4], hw_address: [u8; 6]) {
        self.pool
            .get_mut(&ip_addr.into())
            .unwrap()
            .replace(Address::new(hw_address));
    }

    fn create_pool(subnet: [u8; 4], mask: [u8; 4]) -> DhcpRange {
        let mut pool = BTreeMap::new();

        let octet_ranges = [255 - mask[0], 255 - mask[1], 255 - mask[2], 255 - mask[3]];

        for i in 0..=octet_ranges[0] {
            for ii in 0..=octet_ranges[1] {
                for iii in 0..=octet_ranges[2] {
                    for iiii in 0..=octet_ranges[3] {
                        let ip = std::net::Ipv4Addr::from([
                            (subnet[0] & mask[0]) + i,
                            (subnet[1] & mask[1]) + ii,
                            (subnet[2] & mask[2]) + iii,
                            (subnet[3] & mask[3]) + iiii,
                        ]);
                        pool.insert(ip, None);
                    }
                }
            }
        }
        pool
    }
}
