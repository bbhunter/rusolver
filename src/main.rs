use {
    clap::Parser,
    rusolver::{args::Args, dnslib, structs, utils},
    std::{collections::HashSet, process::ExitCode},
    tokio::io::{self, AsyncReadExt},
};

// WIP: add support for TXT, SRV, NAPTR, PTR, DNAME, MX, NS, SOA, LOC, SVCB,
// HTTPS, SPF, CAA and AVC resource records, selected with a -t/--type option.

/// Resolvers used when none are given, and always used to confirm answers.
const BUILT_IN_NAMESERVERS: [&str; 10] = [
    // Cloudflare
    "1.1.1.1:53",
    "1.0.0.1:53",
    // Google
    "8.8.8.8:53",
    "8.8.4.4:53",
    // Quad9
    "9.9.9.9:53",
    "149.112.112.112:53",
    // OpenDNS
    "208.67.222.222:53",
    "208.67.220.220:53",
    // Verisign
    "64.6.64.6:53",
    "64.6.65.6:53",
];

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let args = Args::parse();
    let ip_version = args.ip_version.into();
    let options = utils::return_resolver_opts(args.timeout, args.retries, ip_version);

    let built_in: HashSet<String> = BUILT_IN_NAMESERVERS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();

    let nameserver_ips = match args.resolvers.as_deref() {
        Some(path) => utils::return_file_lines(path)
            .await
            .map_err(|e| format!("Error reading the resolvers file {path}: {e}"))?,
        None => built_in.clone(),
    };
    if nameserver_ips.is_empty() {
        return Err("The resolvers file did not contain any usable address.".to_owned());
    }

    let resolvers = dnslib::return_tokio_asyncresolver(&nameserver_ips, options.clone())
        .map_err(|e| e.to_string())?;
    let trustable_resolvers =
        dnslib::return_tokio_asyncresolver(&built_in, options).map_err(|e| e.to_string())?;

    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .await
        .map_err(|e| format!("Error reading standard input: {e}"))?;

    let mut wildcard_ips = HashSet::new();
    let hosts: HashSet<String> = match args.domain.as_deref() {
        Some(domain) => {
            // The same resolvers that will do the work: a wildcard address is
            // only meaningful for the view of DNS this run actually queries.
            wildcard_ips =
                utils::detect_wildcards(domain, &resolvers, ip_version, args.quiet_flag).await;
            buffer
                .lines()
                .map(str::trim)
                .filter(|word| !word.is_empty())
                .map(|word| format!("{word}.{domain}"))
                .collect()
        }
        None => buffer
            .lines()
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .map(str::to_owned)
            .collect(),
    };

    let options = structs::LibOptions {
        hosts,
        resolvers,
        trustable_resolvers,
        wildcard_ips,
        enable_double_check: args.enable_double_check,
        threads: args.threads,
        ip_version,
        show_ip_address: args.ip,
        print_results: true,
        quiet_flag: args.quiet_flag,
    };

    dnslib::return_hosts_data(&options).await;
    Ok(())
}
