#[allow(unused)]
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum ParameterRequest {
    SubnetMask = 1,
    TimeOffset = 2,
    Router = 3,
    TimeServer = 4,
    NameServer = 5,
    DomainNameServer = 6,
    HostName = 12,
    BootFileSize = 13,
    DomainName = 15,
    RootPath = 17,
    ExtensionsPath = 18,
    MaxDatagramReassmblySize = 22,
    DefaultIpTtl = 23,
    BroadcastAddress = 28,
    PerformRouterDiscover = 31,
    StaticRoute = 33,
    NetworkInformationServiceDomain = 40,
    NetworkInformationServiceServers = 41,
    NtpServers = 42,
    VendorSpecificInfo = 43,
    NetBiosNameServer = 44,
    NetBiosNodeType = 46,
    NetBiosScope = 47,
    RequestedIpAddress = 50,
    IpAddressLease = 51,
    DhcpServerIndentifier = 54,
    RenewalTimeValue = 58,
    RebindingTimeValue = 59,
    VendorClassIndentifier = 60,
    TftpServerName = 66,
    BootfileName = 67,
    UUIDBasedClientIdentifier = 97,
    DomainSearch = 119,
    ClasslessStaticRoute = 121,
    DocsisFullSecurityServerIp = 128,
    PxeUndefined1 = 129,
    PxeUndefined2 = 130,
    PxeUndefined3 = 131,
    PxeUndefined4 = 132,
    PxeUndefined5 = 133,
    PxeUndefined6 = 134,
    PxeUndefined7 = 135,
    ClasslessStaticRouteMicrosoft = 249,
    ProxyAutodiscovery = 252,
}

impl From<u8> for ParameterRequest {
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
            }
        }
    }
}
