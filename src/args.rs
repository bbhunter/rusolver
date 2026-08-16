use {
    crate::structs::IpVersion,
    clap::{Parser, ValueEnum},
};

/// Address families accepted on the command line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum IpVersionArg {
    /// A records only.
    #[default]
    V4,
    /// AAAA records only.
    V6,
    /// Both, queried concurrently.
    Both,
}

impl From<IpVersionArg> for IpVersion {
    fn from(value: IpVersionArg) -> Self {
        match value {
            IpVersionArg::V4 => Self::V4,
            IpVersionArg::V6 => Self::V6,
            IpVersionArg::Both => Self::Both,
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(
        short,
        long,
        default_value_t = 100,
        help = "Number of concurrent lookups. Default: 100"
    )]
    pub threads: usize,

    #[arg(
        long,
        default_value_t = 0,
        help = "Number of retries after lookup failure before giving up. Defaults to 0"
    )]
    pub retries: usize,

    #[arg(
        short,
        long,
        help = "Target domain. When it's specified, a wordlist can be used from stdin for bruteforcing."
    )]
    pub domain: Option<String>,

    #[arg(short, long, help = "File with DNS ips.")]
    pub resolvers: Option<String>,

    #[arg(long, default_value_t = 3, help = "Timeout in seconds. Default: 3")]
    pub timeout: u64,

    #[arg(
        long,
        value_enum,
        default_value_t = IpVersionArg::V4,
        help = "Address family to look up. Default: v4"
    )]
    pub ip_version: IpVersionArg,

    #[arg(short, long, help = "Display the record data.")]
    pub ip: bool,

    #[arg(
        short,
        long,
        help = "Enable the double verification algorithm for subdomains. Default: false"
    )]
    pub enable_double_check: bool,

    #[arg(short, long, help = "Quiet mode, no output except errors.")]
    pub quiet_flag: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_argument_maps_to_the_family_it_names() {
        assert_eq!(IpVersion::from(IpVersionArg::V4), IpVersion::V4);
        assert_eq!(IpVersion::from(IpVersionArg::V6), IpVersion::V6);
        assert_eq!(IpVersion::from(IpVersionArg::Both), IpVersion::Both);
    }

    #[test]
    fn the_command_line_is_well_formed() {
        use clap::CommandFactory;
        Args::command().debug_assert();
    }
}
