//! This is where we delcare our structs and logic for storage of IP Addresses
use crate::error::{Error, Result};
use crate::types::MacAddr;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// Wrapper for readability
type DhcpRange = BTreeMap<Ipv4Addr, Option<Client>>;

/// Remove magic numbers for IP Addr length
const IP_ADDR_LEN: usize = 4;

#[derive(Debug, PartialEq, Eq)]
pub struct Client {
    mac_address: MacAddr,
    lease_time: u16,
}

impl Client {
    fn new(mac_address: &MacAddr) -> Self {
        Self {
            mac_address: *mac_address,
            lease_time: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AddrPoolConfig {
    router: Option<Ipv4Addr>,
    server_ip: Option<Ipv4Addr>,
    lease_time: u32,
}

impl AddrPoolConfig {
    pub fn router(&self) -> Option<Ipv4Addr> {
        self.router
    }

    pub fn server_ip(&self) -> Option<Ipv4Addr> {
        self.server_ip
    }

    pub fn lease_time(&self) -> u32 {
        self.lease_time
    }

    pub fn set_router(&mut self, ip_addr: impl Into<Ipv4Addr>) -> &mut Self {
        self.router = Some(ip_addr.into());
        self
    }

    pub fn set_server_ip(&mut self, ip_addr: impl Into<Ipv4Addr>) -> &mut Self {
        self.server_ip = Some(ip_addr.into());
        self
    }

    pub fn builder() -> Self {
        Self {
            router: None,
            server_ip: None,
            lease_time: 43200,
        }
    }

    pub fn build(&self) -> AddrPoolConfig {
        *self
    }
}

#[derive(Debug)]
pub struct AddrPool {
    subnet: Ipv4Addr,
    mask: Ipv4Addr,
    pool: DhcpRange,
    config: AddrPoolConfig,
}

impl AddrPool {
    pub fn new(
        subnet: Ipv4Addr,
        mask: Ipv4Addr,
        start: Ipv4Addr,
        end: Ipv4Addr,
        config: AddrPoolConfig,
    ) -> Self {
        Self {
            subnet,
            mask,
            pool: Self::initialise_range(start, end),
            config,
        }
    }

    pub fn config(&self) -> &AddrPoolConfig {
        &self.config
    }

    /// Getter for subnet mask
    pub fn subnet_mask(&self) -> Ipv4Addr {
        self.mask
    }

    /// Request an IP Address from the pool
    pub fn request(&mut self, mac_address: &MacAddr) -> Result<Ipv4Addr> {
        for (ip, client) in self.pool.iter_mut() {
            if client.is_none() {
                *client = Some(Client::new(mac_address));
                return Ok(*ip);
            }
        }
        Err(Error::AllIPAddressesExhausted)
    }

    pub fn lookup(&self, mac_address: &MacAddr, ip_addr: &Ipv4Addr) -> Option<()> {
        if let Some(Some(client)) = self.pool.get(ip_addr) {
            if client.mac_address == *mac_address {
                return Some(());
            } else {
                return None;
            }
        }
        None
    }

    /// Update an existing record
    pub fn update(&mut self, ip_addr: [u8; 4], mac_address: &MacAddr) {
        self.pool
            .get_mut(&ip_addr.into())
            .unwrap()
            .replace(Client::new(mac_address));
    }

    fn initialise_range(start: Ipv4Addr, end: Ipv4Addr) -> DhcpRange {
        let mut pool = BTreeMap::new();
        let start = start.octets();
        let end = end.octets();

        let mut range = [0u8; IP_ADDR_LEN];
        (0..IP_ADDR_LEN).for_each(|octet| range[octet] = end[octet] - start[octet]);

        for i in 0..=range[0] {
            for ii in 0..=range[1] {
                for iii in 0..=range[2] {
                    for iiii in 0..=range[3] {
                        let ip = Ipv4Addr::from([
                            start[0] + i,
                            start[1] + ii,
                            start[2] + iii,
                            start[3] + iiii,
                        ]);
                        pool.insert(ip, None);
                    }
                }
            }
        }

        pool
    }

    fn create_pool_from_subnet(subnet: [u8; 4], mask: [u8; 4]) -> DhcpRange {
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
