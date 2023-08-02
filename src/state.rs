//! This is where we delcare our structs and logic for storage of IP Addresses
use crate::error::{Error, Result};
use crate::types::{DhcpOption, DhcpOptionList, MacAddr};
use crate::DEFAULT_LEASE_TIME;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

/// Wrapper for readability
type DhcpRange = BTreeMap<Ipv4Addr, Option<Client>>;

/// Remove magic numbers for IP Addr length
const IP_ADDR_LEN: usize = 4;

#[derive(Debug, PartialEq, Eq)]
pub struct Client {
    mac_address: MacAddr,
    expires: SystemTime,
}

impl Client {
    fn new(mac_address: &MacAddr, lease_time: u32) -> Self {
        Self {
            mac_address: *mac_address,
            expires: SystemTime::now()
                .checked_add(Duration::from_secs(lease_time as u64))
                .unwrap(),
        }
    }
}

#[derive(Debug)]
pub struct AddrPool<'dhcp_options> {
    subnet: Ipv4Addr,
    pool: DhcpRange,
    options: DhcpOptionList<'dhcp_options>,
}

impl<'dhcp_options> AddrPool<'dhcp_options> {
    pub fn new(
        subnet: impl Into<Ipv4Addr>,
        mask: impl Into<Ipv4Addr>,
        range: (impl Into<Ipv4Addr>, impl Into<Ipv4Addr>),
    ) -> Self {
        let mut options = DhcpOptionList::builder();

        options
            .add(DhcpOption::SubnetMask(mask.into().octets()))
            .add(DhcpOption::End);

        Self {
            subnet: subnet.into(),
            pool: Self::initialise_range(range.0.into(), range.1.into()),
            options,
        }
    }

    pub fn options_mut(&mut self) -> &mut DhcpOptionList<'dhcp_options> {
        &mut self.options
    }

    pub fn options(&self) -> &DhcpOptionList<'dhcp_options> {
        &self.options
    }

    fn allocate_address(&mut self, mac_address: &MacAddr) -> Option<Ipv4Addr> {
        let lease_time = match self.options.get(DhcpOption::LEASE_TIME) {
            Some(DhcpOption::LeaseTime(time)) => time,
            _ => DEFAULT_LEASE_TIME,
        };

        for (ip, client) in &mut self.pool {
            if client.is_none() {
                *client = Some(Client::new(mac_address, lease_time));
                return Some(*ip);
            }
        }

        println!("{:?}", Error::AllIPAddressesExhausted);
        None
    }

    /// Request an IP Address from the pool
    pub fn request(&mut self, mac_address: &MacAddr) -> Ipv4Addr {
        self.lookup_mac(&mac_address).unwrap_or_else(|| {
            self.allocate_address(&mac_address)
                .unwrap_or_else(|| self.evict_oldest_lease(&mac_address))
        })
    }

    fn evict_oldest_lease(&mut self, mac_address: &MacAddr) -> Ipv4Addr {
        let lease_time = match self.options.get(DhcpOption::LEASE_TIME) {
            Some(DhcpOption::LeaseTime(time)) => time,
            _ => DEFAULT_LEASE_TIME,
        };

        let victim = self
            .pool
            .iter()
            .filter(|(_, client)| client.is_some())
            .min_by_key(|(_, client)| client.as_ref().unwrap().expires)
            .unwrap()
            .0
            .to_owned();

        self.pool
            .insert(victim, Some(Client::new(mac_address, lease_time)));

        victim
    }

    fn lookup_mac(&self, mac_addr: &MacAddr) -> Option<Ipv4Addr> {
        self.pool
            .iter()
            .find(|client| {
                if let Some(client) = client.1 {
                    if client.mac_address == *mac_addr {
                        return true;
                    }
                }
                return false;
            })
            .and_then(|(ip, mac)| Some(ip).copied())
    }

    pub fn verify_request(&self, mac_address: &MacAddr, ip_addr: &Ipv4Addr) -> Option<()> {
        if let Some(Some(client)) = self.pool.get(ip_addr) {
            if client.mac_address == *mac_address {
                return Some(());
            } else {
                return None;
            }
        }
        None
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
