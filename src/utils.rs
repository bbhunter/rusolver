use {
    crate::structs::{DomainData, IpVersion, LibOptions},
    futures::stream::{self, StreamExt},
    hickory_resolver::{
        config::{LookupIpStrategy, ResolverOpts, ServerOrderingStrategy},
        proto::rr::RData,
        TokioResolver,
    },
    rand::{
        distr::{Alphanumeric, SampleString},
        rng,
    },
    std::{
        collections::HashSet,
        io::{self, BufWriter, StdoutLock, Write},
        net::IpAddr,
    },
    tokio::{fs::File, io::AsyncReadExt},
};

/// Random hostnames generated when probing for a wildcard record.
const WILDCARD_PROBES: usize = 19;
/// Length of each generated wildcard probe label.
const WILDCARD_LABEL_LEN: usize = 15;
/// Probes kept in flight while detecting wildcards.
const WILDCARD_CONCURRENCY: usize = 10;
/// Port assumed when a resolvers file lists a bare address.
const DEFAULT_DNS_PORT: u16 = 53;

/// Reads nameserver addresses from `file`, one per line.
///
/// Blank lines and `#` comments are skipped, spaces are trimmed, and an entry
/// that already carries a port keeps it.
///
/// # Errors
///
/// Returns the underlying error when the file cannot be read.
pub async fn return_file_lines(file: &str) -> io::Result<HashSet<String>> {
    let mut handle = File::open(file).await?;
    let mut buffer = String::new();
    handle.read_to_string(&mut buffer).await?;

    Ok(buffer
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            if line.contains(':') {
                line.to_owned()
            } else {
                format!("{line}:{DEFAULT_DNS_PORT}")
            }
        })
        .collect())
}

/// Finds the addresses a domain hands out for names that do not exist.
pub async fn detect_wildcards(
    target: &str,
    resolvers: &TokioResolver,
    ip_version: IpVersion,
    quiet_flag: bool,
) -> HashSet<IpAddr> {
    if !quiet_flag {
        println!("Running wildcards detection for {target}...\n");
    }

    let probes: Vec<String> = (0..WILDCARD_PROBES)
        .map(|_| {
            let label = Alphanumeric.sample_string(&mut rng(), WILDCARD_LABEL_LEN);
            format!("{label}.{target}.")
        })
        .collect();

    let wildcard_ips: HashSet<IpAddr> = stream::iter(probes)
        .map(|host| async move {
            let (v4, v6) = tokio::join!(
                async {
                    if ip_version.wants_v4() {
                        resolvers.ipv4_lookup(host.as_str()).await.ok()
                    } else {
                        None
                    }
                },
                async {
                    if ip_version.wants_v6() {
                        resolvers.ipv6_lookup(host.as_str()).await.ok()
                    } else {
                        None
                    }
                }
            );

            let mut found: Vec<IpAddr> = Vec::new();
            for lookup in [v4, v6].into_iter().flatten() {
                found.extend(
                    lookup
                        .answers()
                        .iter()
                        .filter_map(|record| match &record.data {
                            RData::A(address) => Some(IpAddr::V4(address.0)),
                            RData::AAAA(address) => Some(IpAddr::V6(address.0)),
                            _ => None,
                        }),
                );
            }
            found
        })
        .buffer_unordered(WILDCARD_CONCURRENCY)
        .flat_map(stream::iter)
        .collect()
        .await;

    if !quiet_flag {
        if wildcard_ips.is_empty() {
            println!("No wildcards detected for {target}, nice!\n");
        } else {
            println!("Wildcards detected for {target} and wildcard's IP saved for further work.");
            println!("Wildcard IPs: {wildcard_ips:?}\n");
        }
    }
    wildcard_ips
}

/// Buffered destination for the hosts a run confirms.
///
/// One buffer for the whole run: a lock and a write syscall per host costs more
/// than the formatting does.
pub struct Writer {
    sink: Option<BufWriter<StdoutLock<'static>>>,
    show_ip_address: bool,
}

impl Writer {
    /// Opens the writer, silent when the caller prints its own output.
    #[must_use]
    pub fn new(options: &LibOptions) -> Self {
        Self {
            sink: options
                .print_results
                .then(|| BufWriter::new(io::stdout().lock())),
            show_ip_address: options.show_ip_address,
        }
    }

    /// Reports `host` when it resolved to an address of its own.
    ///
    /// Addresses are sorted so repeated runs produce identical output.
    pub fn report(&mut self, host: &str, data: &DomainData) {
        let Some(sink) = self.sink.as_mut() else {
            return;
        };
        if data.is_wildcard || !data.has_addresses() {
            return;
        }

        if !self.show_ip_address {
            let _ = writeln!(sink, "{host}");
            return;
        }

        let mut addresses: Vec<IpAddr> = data
            .ipv4_addresses
            .iter()
            .map(|ip| IpAddr::V4(*ip))
            .chain(data.ipv6_addresses.iter().map(|ip| IpAddr::V6(*ip)))
            .collect();
        addresses.sort_unstable();

        let _ = write!(sink, "{host}");
        for address in addresses {
            let _ = write!(sink, ",{address}");
        }
        let _ = writeln!(sink);
    }

    /// Flushes whatever is still buffered.
    pub fn finish(mut self) {
        if let Some(sink) = self.sink.as_mut() {
            let _ = sink.flush();
        }
    }
}

/// Resolver settings for the requested address family.
#[must_use]
pub fn return_resolver_opts(timeout: u64, retries: usize, ip_version: IpVersion) -> ResolverOpts {
    let mut options = ResolverOpts::default();
    options.timeout = std::time::Duration::from_secs(timeout);
    options.attempts = retries;
    options.ip_strategy = match ip_version {
        IpVersion::V4 => LookupIpStrategy::Ipv4Only,
        IpVersion::V6 => LookupIpStrategy::Ipv6Only,
        IpVersion::Both => LookupIpStrategy::Ipv4AndIpv6,
    };
    // One nameserver per question; the useful concurrency is across hosts.
    options.num_concurrent_reqs = 1;
    options.server_ordering_strategy = ServerOrderingStrategy::RoundRobin;
    options
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str, contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("rusolver-test-{name}"));
        let mut file = std::fs::File::create(&path).expect("create the fixture");
        file.write_all(contents.as_bytes()).expect("write it");
        path
    }

    #[tokio::test]
    async fn a_resolvers_file_is_read_into_addressable_entries() {
        let path = temp_file(
            "resolvers",
            "1.1.1.1\n  8.8.8.8  \n\n# a comment\n9.9.9.9:5353\n",
        );
        let lines = return_file_lines(path.to_str().expect("utf8 path"))
            .await
            .expect("the file exists");

        assert_eq!(lines.len(), 3);
        assert!(lines.contains("1.1.1.1:53"), "a bare address gains a port");
        assert!(lines.contains("8.8.8.8:53"), "spaces are trimmed");
        assert!(
            lines.contains("9.9.9.9:5353"),
            "an explicit port is not given a second one"
        );
        assert!(!lines.iter().any(|l| l.contains("comment")));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn a_missing_resolvers_file_is_an_error_and_not_an_exit() {
        assert!(return_file_lines("/definitely/not/here").await.is_err());
    }

    #[test]
    fn the_resolver_strategy_follows_the_requested_family() {
        assert_eq!(
            return_resolver_opts(3, 2, IpVersion::V4).ip_strategy,
            LookupIpStrategy::Ipv4Only
        );
        assert_eq!(
            return_resolver_opts(3, 2, IpVersion::V6).ip_strategy,
            LookupIpStrategy::Ipv6Only
        );
        assert_eq!(
            return_resolver_opts(3, 2, IpVersion::Both).ip_strategy,
            LookupIpStrategy::Ipv4AndIpv6
        );
    }

    #[test]
    fn the_timeout_and_retries_reach_the_resolver() {
        let options = return_resolver_opts(7, 4, IpVersion::V4);
        assert_eq!(options.timeout, std::time::Duration::from_secs(7));
        assert_eq!(options.attempts, 4);
    }
}
