use {
    crate::{
        structs::{DomainData, LibOptions},
        utils::Writer,
    },
    futures::stream::{self, StreamExt},
    hickory_resolver::{
        config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts},
        net::runtime::TokioRuntimeProvider,
        proto::rr::{RData, RecordType},
        TokioResolver,
    },
    std::{
        collections::{HashMap, HashSet},
        fmt,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4},
    },
};

/// A resolver that could not be built.
#[derive(Debug)]
pub struct BadNameserver {
    pub address: String,
    pub reason: String,
}

impl fmt::Display for BadNameserver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} is not a usable nameserver address: {}. Only `IPv4:port` is accepted.",
            self.address, self.reason
        )
    }
}

impl std::error::Error for BadNameserver {}

/// Builds a resolver over `nameserver_ips`.
///
/// # Errors
///
/// Returns the offending entry when an address is not `IPv4:port`. These come
/// straight from a file or a command line, so a typo must not end the process.
pub fn return_tokio_asyncresolver<S: ::std::hash::BuildHasher>(
    nameserver_ips: &HashSet<String, S>,
    options: ResolverOpts,
) -> Result<TokioResolver, BadNameserver> {
    let mut name_servers = Vec::with_capacity(nameserver_ips.len());

    for server in nameserver_ips {
        let socket = server.parse::<SocketAddrV4>().map_err(|e| BadNameserver {
            address: server.clone(),
            reason: e.to_string(),
        })?;

        let mut connection = ConnectionConfig::udp();
        connection.port = socket.port();

        let mut name_server = NameServerConfig::udp(IpAddr::V4(*socket.ip()));
        name_server.trust_negative_responses = false;
        name_server.connections = vec![connection];

        name_servers.push(name_server);
    }

    TokioResolver::builder_with_config(
        ResolverConfig::from_parts(None, vec![], name_servers),
        TokioRuntimeProvider::default(),
    )
    .with_options(options)
    .build()
    .map_err(|e| BadNameserver {
        address: "the configured nameservers".to_owned(),
        reason: e.to_string(),
    })
}

/// How many lookups to keep in flight.
///
/// Never zero: `buffer_unordered(0)` has no slot for a future, so it polls
/// nothing and the stream never finishes.
#[must_use]
pub fn concurrency(requested: usize, work: usize) -> usize {
    requested.min(work).max(1)
}

/// Turns a host into the absolute name a resolver expects.
fn fqdn_of(host: &str) -> String {
    let trimmed = host.trim_end_matches('.');
    let mut name = String::with_capacity(trimmed.len() + 1);
    name.push_str(trimmed);
    name.push('.');
    name
}

/// Collects the IPv4 answers of a lookup.
fn v4_answers(lookup: &hickory_resolver::lookup::Lookup) -> HashSet<Ipv4Addr> {
    lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(address) => Some(address.0),
            _ => None,
        })
        .collect()
}

/// Collects the IPv6 answers of a lookup.
fn v6_answers(lookup: &hickory_resolver::lookup::Lookup) -> HashSet<Ipv6Addr> {
    lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::AAAA(address) => Some(address.0),
            _ => None,
        })
        .collect()
}

/// Looks up the A records of `fqdn`.
async fn lookup_v4(options: &LibOptions, fqdn: &str) -> HashSet<Ipv4Addr> {
    if options.enable_double_check {
        let (probe, confirmation) = tokio::join!(
            options.resolvers.ipv4_lookup(fqdn),
            options.trustable_resolvers.ipv4_lookup(fqdn)
        );
        match (probe, confirmation) {
            (Ok(_), Ok(confirmed)) => v4_answers(&confirmed),
            _ => HashSet::new(),
        }
    } else {
        options
            .resolvers
            .ipv4_lookup(fqdn)
            .await
            .map(|lookup| v4_answers(&lookup))
            .unwrap_or_default()
    }
}

/// Looks up the AAAA records of `fqdn`.
async fn lookup_v6(options: &LibOptions, fqdn: &str) -> HashSet<Ipv6Addr> {
    if options.enable_double_check {
        let (probe, confirmation) = tokio::join!(
            options.resolvers.ipv6_lookup(fqdn),
            options.trustable_resolvers.ipv6_lookup(fqdn)
        );
        match (probe, confirmation) {
            (Ok(_), Ok(confirmed)) => v6_answers(&confirmed),
            _ => HashSet::new(),
        }
    } else {
        options
            .resolvers
            .ipv6_lookup(fqdn)
            .await
            .map(|lookup| v6_answers(&lookup))
            .unwrap_or_default()
    }
}

/// Resolves one host into the addresses it answers with.
async fn lookup_one(options: &LibOptions, host: &str) -> DomainData {
    let fqdn = fqdn_of(host);
    let want_v4 = options.ip_version.wants_v4();
    let want_v6 = options.ip_version.wants_v6();

    let (ipv4_addresses, ipv6_addresses) = tokio::join!(
        async {
            if want_v4 {
                lookup_v4(options, &fqdn).await
            } else {
                HashSet::new()
            }
        },
        async {
            if want_v6 {
                lookup_v6(options, &fqdn).await
            } else {
                HashSet::new()
            }
        }
    );

    let mut data = DomainData {
        ipv4_addresses,
        ipv6_addresses,
        ..DomainData::default()
    };
    data.mark_wildcard(&options.wildcard_ips);
    data
}

/// Resolves every host in `options`.
pub async fn return_hosts_data(options: &LibOptions) -> HashMap<String, DomainData> {
    if options.hosts.is_empty() {
        return HashMap::new();
    }

    let threads = concurrency(options.threads, options.hosts.len());
    let mut found = HashMap::with_capacity(options.hosts.len());

    let mut lookups = stream::iter(options.hosts.iter())
        .map(|host| async move { (host, lookup_one(options, host).await) })
        .buffer_unordered(threads);

    let mut out = Writer::new(options);
    while let Some((host, data)) = lookups.next().await {
        out.report(host, &data);
        found.insert(host.clone(), data);
    }
    out.finish();

    found
}

/// Looks up the CNAME of every host, keeping only the hosts that have one.
pub async fn return_cname_data<S: ::std::hash::BuildHasher>(
    hosts: &HashSet<String, S>,
    resolver: &TokioResolver,
    trustable_resolver: &TokioResolver,
    enable_double_check: bool,
    threads: usize,
) -> HashMap<String, String> {
    if hosts.is_empty() {
        return HashMap::new();
    }

    let threads = concurrency(threads, hosts.len());

    stream::iter(hosts.iter())
        .map(|host| async move {
            let fqdn = fqdn_of(host);

            let lookup = if enable_double_check {
                let (probe, confirmation) = tokio::join!(
                    resolver.lookup(fqdn.as_str(), RecordType::CNAME),
                    trustable_resolver.lookup(fqdn.as_str(), RecordType::CNAME)
                );
                match (probe, confirmation) {
                    (Ok(_), Ok(confirmed)) => Some(confirmed),
                    _ => None,
                }
            } else {
                resolver.lookup(fqdn.as_str(), RecordType::CNAME).await.ok()
            };

            let cname = lookup
                .and_then(|lookup| {
                    lookup
                        .answers()
                        .iter()
                        .find_map(|record| match &record.data {
                            RData::CNAME(name) => Some(name.to_string()),
                            _ => None,
                        })
                })
                .unwrap_or_default();

            (host.trim_end_matches('.').to_owned(), cname)
        })
        .buffer_unordered(threads)
        .filter(|(_, cname)| {
            let has_alias = !cname.is_empty();
            async move { has_alias }
        })
        .collect()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrency_is_never_zero() {
        assert_eq!(concurrency(0, 100), 1);
        assert_eq!(concurrency(100, 0), 1);
        assert_eq!(concurrency(0, 0), 1);
    }

    #[test]
    fn concurrency_never_exceeds_the_work_available() {
        assert_eq!(concurrency(100, 7), 7);
        assert_eq!(concurrency(7, 100), 7);
        assert_eq!(concurrency(usize::MAX, 3), 3);
    }

    #[test]
    fn a_host_becomes_an_absolute_name_exactly_once() {
        assert_eq!(fqdn_of("example.com"), "example.com.");
        assert_eq!(fqdn_of("example.com."), "example.com.");
        assert_eq!(fqdn_of("example.com..."), "example.com.");
        assert_eq!(fqdn_of(""), ".");
    }

    #[test]
    fn a_malformed_nameserver_is_an_error_and_not_a_crash() {
        let opts = ResolverOpts::default();
        for bad in ["not-an-ip", "1.1.1.1", "1.1.1.1:53:53", "", "[::1]:53"] {
            let servers = HashSet::from([bad.to_owned()]);
            let error = return_tokio_asyncresolver(&servers, opts.clone())
                .expect_err(&format!("{bad} must be rejected"));
            assert_eq!(error.address, bad);
        }
    }

    #[test]
    fn well_formed_nameservers_build_a_resolver() {
        let servers = HashSet::from(["1.1.1.1:53".to_owned(), "8.8.8.8:5353".to_owned()]);
        assert!(return_tokio_asyncresolver(&servers, ResolverOpts::default()).is_ok());
    }
}
