use {
    hickory_resolver::TokioResolver,
    std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
    },
};

/// Address families to ask for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum IpVersion {
    /// A records only.
    #[default]
    V4,
    /// AAAA records only.
    V6,
    /// Both, queried concurrently.
    Both,
}

impl IpVersion {
    /// Reports whether A records are wanted.
    #[must_use]
    pub const fn wants_v4(self) -> bool {
        matches!(self, Self::V4 | Self::Both)
    }

    /// Reports whether AAAA records are wanted.
    #[must_use]
    pub const fn wants_v6(self) -> bool {
        matches!(self, Self::V6 | Self::Both)
    }
}

/// What was learned about one host.
///
/// Addresses are parsed values, not text: no allocation per address, cheaper
/// hashing, and an ordering that keeps the reported address stable.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DomainData {
    pub ipv4_addresses: HashSet<Ipv4Addr>,
    pub ipv6_addresses: HashSet<Ipv6Addr>,
    pub cname: String,
    /// Every address of this host is one the wildcard record also answers with.
    pub is_wildcard: bool,
}

impl DomainData {
    /// Reports whether the host resolved to anything at all.
    #[must_use]
    pub fn has_addresses(&self) -> bool {
        !self.ipv4_addresses.is_empty() || !self.ipv6_addresses.is_empty()
    }

    /// The lowest IPv4 address, so repeated runs report the same one.
    #[must_use]
    pub fn primary_ipv4(&self) -> Option<Ipv4Addr> {
        self.ipv4_addresses.iter().min().copied()
    }

    /// The lowest IPv6 address, chosen as in [`Self::primary_ipv4`].
    #[must_use]
    pub fn primary_ipv6(&self) -> Option<Ipv6Addr> {
        self.ipv6_addresses.iter().min().copied()
    }

    /// Marks the host as a wildcard when every address it has is one the
    /// wildcard record answers with.
    ///
    /// A host with no addresses is not one, though "all of nothing" is true.
    pub fn mark_wildcard(&mut self, wildcard_ips: &HashSet<IpAddr>) {
        self.is_wildcard = self.has_addresses()
            && self
                .ipv4_addresses
                .iter()
                .all(|ip| wildcard_ips.contains(&IpAddr::V4(*ip)))
            && self
                .ipv6_addresses
                .iter()
                .all(|ip| wildcard_ips.contains(&IpAddr::V6(*ip)));
    }
}

/// Everything a lookup run needs.
#[derive(Clone, Debug)]
pub struct LibOptions {
    pub hosts: HashSet<String>,
    pub resolvers: TokioResolver,
    pub trustable_resolvers: TokioResolver,
    pub wildcard_ips: HashSet<IpAddr>,
    /// Require the trustable resolvers to confirm every answer.
    pub enable_double_check: bool,
    pub threads: usize,
    pub ip_version: IpVersion,
    pub show_ip_address: bool,
    /// Print each confirmed host as it is found.
    ///
    /// Separate from [`Self::quiet_flag`]: the command line wants results
    /// without commentary, a library caller wants neither.
    pub print_results: bool,
    /// Suppress progress commentary such as the wildcard notice.
    pub quiet_flag: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(text: &str) -> Ipv4Addr {
        text.parse().expect("a valid address")
    }

    #[test]
    fn a_host_without_addresses_is_never_a_wildcard() {
        let mut data = DomainData::default();
        data.mark_wildcard(&HashSet::from([IpAddr::V4(v4("1.2.3.4"))]));
        assert!(!data.is_wildcard);
    }

    #[test]
    fn a_host_answering_only_wildcard_addresses_is_a_wildcard() {
        let mut data = DomainData {
            ipv4_addresses: HashSet::from([v4("1.2.3.4")]),
            ..DomainData::default()
        };
        data.mark_wildcard(&HashSet::from([IpAddr::V4(v4("1.2.3.4"))]));
        assert!(data.is_wildcard);
    }

    #[test]
    fn one_address_of_its_own_is_enough_to_not_be_a_wildcard() {
        let mut data = DomainData {
            ipv4_addresses: HashSet::from([v4("1.2.3.4"), v4("5.6.7.8")]),
            ..DomainData::default()
        };
        data.mark_wildcard(&HashSet::from([IpAddr::V4(v4("1.2.3.4"))]));
        assert!(!data.is_wildcard);
    }

    #[test]
    fn the_reported_address_does_not_change_between_runs() {
        let forwards = DomainData {
            ipv4_addresses: HashSet::from([v4("10.0.0.1"), v4("10.0.0.2"), v4("10.0.0.3")]),
            ..DomainData::default()
        };
        let backwards = DomainData {
            ipv4_addresses: HashSet::from([v4("10.0.0.3"), v4("10.0.0.2"), v4("10.0.0.1")]),
            ..DomainData::default()
        };
        assert_eq!(forwards.primary_ipv4(), Some(v4("10.0.0.1")));
        assert_eq!(forwards.primary_ipv4(), backwards.primary_ipv4());
        assert_eq!(DomainData::default().primary_ipv4(), None);
    }

    #[test]
    fn each_version_asks_for_what_it_names() {
        assert!(IpVersion::V4.wants_v4() && !IpVersion::V4.wants_v6());
        assert!(!IpVersion::V6.wants_v4() && IpVersion::V6.wants_v6());
        assert!(IpVersion::Both.wants_v4() && IpVersion::Both.wants_v6());
        assert_eq!(IpVersion::default(), IpVersion::V4);
    }
}
