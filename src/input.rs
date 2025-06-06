//! Provides a means to read, parse and hold configuration options for scans.
use clap::{Parser, ValueEnum};
use serde_derive::Deserialize;
use std::fs;
use std::path::PathBuf;

const LOWEST_PORT_NUMBER: u16 = 1;
const TOP_PORT_NUMBER: u16 = 65535;

/// Represents the strategy in which the port scanning will run.
///   - Serial will run from start to end, for example 1 to 1_000.
///   - Random will randomize the order in which ports will be scanned.
#[derive(Deserialize, Debug, ValueEnum, Clone, Copy, PartialEq, Eq)]
pub enum ScanOrder {
    Serial,
    Random,
}

/// Represents the scripts variant.
///   - none will avoid running any script, only portscan results will be shown.
///   - default will run the default embedded nmap script, that's part of RustScan since the beginning.
///   - custom will read the ScriptConfig file and the available scripts in the predefined folders
#[derive(Deserialize, Debug, ValueEnum, Clone, PartialEq, Eq, Copy)]
pub enum ScriptsRequired {
    None,
    Default,
    Custom,
}

/// Represents the range of ports to be scanned.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[cfg(not(tarpaulin_include))]
fn parse_range(input: &str) -> Result<PortRange, String> {
    let range = input
        .split('-')
        .map(str::parse)
        .collect::<Result<Vec<u16>, std::num::ParseIntError>>();

    if range.is_err() {
        return Err(String::from(
            "the range format must be 'start-end'. Example: 1-1000.",
        ));
    }

    match range.unwrap().as_slice() {
        [start, end] => Ok(PortRange {
            start: *start,
            end: *end,
        }),
        _ => Err(String::from(
            "the range format must be 'start-end'. Example: 1-1000.",
        )),
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "rustscan",
    version = env!("CARGO_PKG_VERSION"),
    max_term_width = 120,
    help_template = "{bin} {version}\n{about}\n\nUSAGE:\n    {usage}\n\nOPTIONS:\n{options}",
)]
#[allow(clippy::struct_excessive_bools)]
/// Fast Port Scanner built in Rust.
/// WARNING Do not use this program against sensitive infrastructure since the
/// specified server may not be able to handle this many socket connections at once.
/// - Discord  <http://discord.skerritt.blog>
/// - GitHub <https://github.com/RustScan/RustScan>
pub struct Opts {
    /// A comma-delimited list or newline-delimited file of separated CIDRs, IPs, or hosts to be scanned.
    #[arg(short, long, value_delimiter = ',')]
    pub addresses: Vec<String>,

    /// A list of comma separated ports to be scanned. Example: 80,443,8080.
    #[arg(short, long, value_delimiter = ',')]
    pub ports: Option<Vec<u16>>,

    /// A range of ports with format start-end. Example: 1-1000.
    #[arg(short, long, conflicts_with = "ports", value_parser = parse_range)]
    pub range: Option<PortRange>,

    /// Whether to ignore the configuration file or not.
    #[arg(short, long)]
    pub no_config: bool,

    /// Hide the banner
    #[arg(long)]
    pub no_banner: bool,

    /// Custom path to config file
    #[arg(short, long, value_parser)]
    pub config_path: Option<PathBuf>,

    /// Greppable mode. Only output the ports. No Nmap. Useful for grep or outputting to a file.
    #[arg(short, long)]
    pub greppable: bool,

    /// Accessible mode. Turns off features which negatively affect screen readers.
    #[arg(long)]
    pub accessible: bool,

    /// A comma-delimited list or file of DNS resolvers.
    #[arg(long)]
    pub resolver: Option<String>,

    /// The batch size for port scanning, it increases or slows the speed of
    /// scanning. Depends on the open file limit of your OS.  If you do 65535
    /// it will do every port at the same time. Although, your OS may not
    /// support this.
    #[arg(short, long, default_value = "4500")]
    pub batch_size: u16,

    /// The timeout in milliseconds before a port is assumed to be closed.
    #[arg(short, long, default_value = "1500")]
    pub timeout: u32,

    /// The number of tries before a port is assumed to be closed.
    /// If set to 0, rustscan will correct it to 1.
    #[arg(long, default_value = "1")]
    pub tries: u8,

    /// Automatically ups the ULIMIT with the value you provided.
    #[arg(short, long)]
    pub ulimit: Option<u64>,

    /// The order of scanning to be performed. The "serial" option will
    /// scan ports in ascending order while the "random" option will scan
    /// ports randomly.
    #[arg(long, value_enum, ignore_case = true, default_value = "serial")]
    pub scan_order: ScanOrder,

    /// Level of scripting required for the run.
    #[arg(long, value_enum, ignore_case = true, default_value = "default")]
    pub scripts: ScriptsRequired,

    /// Use the top 1000 ports.
    #[arg(long)]
    pub top: bool,

    /// The Script arguments to run.
    /// To use the argument -A, end RustScan's args with '-- -A'.
    /// Example: 'rustscan -t 1500 -a 127.0.0.1 -- -A -sC'.
    /// This command adds -Pn -vvv -p $PORTS automatically to nmap.
    /// For things like --script '(safe and vuln)' enclose it in quotations marks \"'(safe and vuln)'\"
    #[arg(last = true)]
    pub command: Vec<String>,

    /// A list of comma separated ports to be excluded from scanning. Example: 80,443,8080.
    #[arg(short, long, value_delimiter = ',')]
    pub exclude_ports: Option<Vec<u16>>,

    /// A list of comma separated CIDRs, IPs, or hosts to be excluded from scanning.
    #[arg(short = 'x', long = "exclude-addresses", value_delimiter = ',')]
    pub exclude_addresses: Option<Vec<String>>,

    /// UDP scanning mode, finds UDP ports that send back responses
    #[arg(long)]
    pub udp: bool,
}

#[cfg(not(tarpaulin_include))]
impl Opts {
    pub fn read() -> Self {
        let mut opts = Opts::parse();

        if opts.ports.is_none() && opts.range.is_none() {
            opts.range = Some(PortRange {
                start: LOWEST_PORT_NUMBER,
                end: TOP_PORT_NUMBER,
            });
        }

        opts
    }

    /// Reads the command line arguments into an Opts struct and merge
    /// values found within the user configuration file.
    pub fn merge(&mut self, config: &Config) {
        if !self.no_config {
            self.merge_required(config);
            self.merge_optional(config);
        }
    }

    fn merge_required(&mut self, config: &Config) {
        macro_rules! merge_required {
            ($($field: ident),+) => {
                $(
                    if let Some(e) = &config.$field {
                        self.$field = e.clone();
                    }
                )+
            }
        }

        merge_required!(
            addresses, greppable, accessible, batch_size, timeout, tries, scan_order, scripts,
            command, udp
        );
    }

    fn merge_optional(&mut self, config: &Config) {
        macro_rules! merge_optional {
            ($($field: ident),+) => {
                $(
                    if config.$field.is_some() {
                        self.$field = config.$field.clone();
                    }
                )+
            }
        }

        // Only use top ports when the user asks for them
        if self.top && config.ports.is_some() {
            self.ports = config.ports.clone();
        }

        merge_optional!(range, resolver, ulimit, exclude_ports, exclude_addresses);
    }
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            addresses: vec![],
            ports: None,
            range: None,
            greppable: true,
            batch_size: 0,
            timeout: 0,
            tries: 0,
            ulimit: None,
            command: vec![],
            accessible: false,
            resolver: None,
            scan_order: ScanOrder::Serial,
            no_config: true,
            no_banner: false,
            top: false,
            scripts: ScriptsRequired::Default,
            config_path: None,
            exclude_ports: None,
            exclude_addresses: None,
            udp: false,
        }
    }
}

/// Struct used to deserialize the options specified within our config file.
/// These will be further merged with our command line arguments in order to
/// generate the final Opts struct.
#[cfg(not(tarpaulin_include))]
#[derive(Debug, Deserialize)]
pub struct Config {
    addresses: Option<Vec<String>>,
    ports: Option<Vec<u16>>,
    range: Option<PortRange>,
    greppable: Option<bool>,
    accessible: Option<bool>,
    batch_size: Option<u16>,
    timeout: Option<u32>,
    tries: Option<u8>,
    ulimit: Option<u64>,
    resolver: Option<String>,
    scan_order: Option<ScanOrder>,
    command: Option<Vec<String>>,
    scripts: Option<ScriptsRequired>,
    exclude_ports: Option<Vec<u16>>,
    exclude_addresses: Option<Vec<String>>,
    udp: Option<bool>,
}

#[cfg(not(tarpaulin_include))]
#[allow(clippy::doc_link_with_quotes)]
#[allow(clippy::manual_unwrap_or_default)]
impl Config {
    /// Reads the configuration file with TOML format and parses it into a
    /// Config struct.
    ///
    /// # Format
    ///
    /// addresses = ["127.0.0.1", "127.0.0.1"]
    /// ports = [80, 443, 8080]
    /// greppable = true
    /// scan_order = "Serial"
    /// exclude_ports = [8080, 9090, 80]
    /// udp = false
    ///
    pub fn read(custom_config_path: Option<PathBuf>) -> Self {
        let mut content = String::new();
        let config_path = custom_config_path.unwrap_or_else(default_config_path);
        if config_path.exists() {
            content = match fs::read_to_string(config_path) {
                Ok(content) => content,
                Err(_) => String::new(),
            }
        }

        let config: Config = match toml::from_str(&content) {
            Ok(config) => config,
            Err(e) => {
                println!("Found {e} in configuration file.\nAborting scan.\n");
                std::process::exit(1);
            }
        };

        config
    }
}

/// Constructs default path to config toml
pub fn default_config_path() -> PathBuf {
    let Some(mut config_path) = dirs::home_dir() else {
        panic!("Could not infer config file path.");
    };
    config_path.push(".rustscan.toml");
    config_path
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};
    use parameterized::parameterized;

    use super::{Config, Opts, PortRange, ScanOrder, ScriptsRequired};

    impl Config {
        fn default() -> Self {
            Self {
                addresses: Some(vec!["127.0.0.1".to_owned()]),
                ports: None,
                range: None,
                greppable: Some(true),
                batch_size: Some(25_000),
                timeout: Some(1_000),
                tries: Some(1),
                ulimit: None,
                command: Some(vec!["-A".to_owned()]),
                accessible: Some(true),
                resolver: None,
                scan_order: Some(ScanOrder::Random),
                scripts: None,
                exclude_ports: None,
                exclude_addresses: None,
                udp: Some(false),
            }
        }
    }

    #[test]
    fn verify_cli() {
        Opts::command().debug_assert();
    }

    #[parameterized(input = {
        vec!["rustscan", "--addresses", "127.0.0.1"],
        vec!["rustscan", "--addresses", "127.0.0.1", "--", "-sCV"],
        vec!["rustscan", "--addresses", "127.0.0.1", "--", "-A"],
        vec!["rustscan", "-t", "1500", "-a", "127.0.0.1", "--", "-A", "-sC"],
        vec!["rustscan", "--addresses", "127.0.0.1", "--", "--script", r#""'(safe and vuln)'""#],
    }, command = {
        vec![],
        vec!["-sCV".to_owned()],
        vec!["-A".to_owned()],
        vec!["-A".to_owned(), "-sC".to_owned()],
        vec!["--script".to_owned(), "\"'(safe and vuln)'\"".to_owned()],
    })]
    fn parse_trailing_command(input: Vec<&str>, command: Vec<String>) {
        let opts = Opts::parse_from(input);

        assert_eq!(vec!["127.0.0.1".to_owned()], opts.addresses);
        assert_eq!(command, opts.command);
    }

    #[test]
    fn opts_no_merge_when_config_is_ignored() {
        let mut opts = Opts::default();
        let config = Config::default();

        opts.merge(&config);

        assert_eq!(opts.addresses, vec![] as Vec<String>);
        assert!(opts.greppable);
        assert!(!opts.accessible);
        assert_eq!(opts.timeout, 0);
        assert_eq!(opts.command, vec![] as Vec<String>);
        assert_eq!(opts.scan_order, ScanOrder::Serial);
    }

    #[test]
    fn opts_merge_required_arguments() {
        let mut opts = Opts::default();
        let config = Config::default();

        opts.merge_required(&config);

        assert_eq!(opts.addresses, config.addresses.unwrap());
        assert_eq!(opts.greppable, config.greppable.unwrap());
        assert_eq!(opts.timeout, config.timeout.unwrap());
        assert_eq!(opts.command, config.command.unwrap());
        assert_eq!(opts.accessible, config.accessible.unwrap());
        assert_eq!(opts.scan_order, config.scan_order.unwrap());
        assert_eq!(opts.scripts, ScriptsRequired::Default);
    }

    #[test]
    fn opts_merge_optional_arguments() {
        let mut opts = Opts::default();
        let mut config = Config::default();
        config.range = Some(PortRange {
            start: 1,
            end: 1_000,
        });
        config.ulimit = Some(1_000);
        config.resolver = Some("1.1.1.1".to_owned());

        opts.merge_optional(&config);

        assert_eq!(opts.range, config.range);
        assert_eq!(opts.ulimit, config.ulimit);
        assert_eq!(opts.resolver, config.resolver);
    }
}
