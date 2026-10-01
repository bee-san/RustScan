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

/// The port ranges to scan, as inclusive `(start, end)` pairs.
///
/// Parsed from `-r/--range` (e.g. `1-500,1000-2500`) and from the `range`
/// key of the configuration file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRanges(pub Vec<(u16, u16)>);

/// Accepted spellings of `range` in the configuration file.
#[derive(Deserialize)]
#[serde(untagged)]
enum PortRangesConfig {
    /// `range = { start = 1, end = 1000 }`: the format used before multiple
    /// ranges were supported, kept so existing configuration files still work.
    Single { start: u16, end: u16 },
    /// `range = "1-500,1000-2500"`: the same syntax as `--range`.
    Text(String),
    /// `range = [[1, 500], [1000, 2500]]`.
    Pairs(Vec<(u16, u16)>),
}

impl<'de> serde::Deserialize<'de> for PortRanges {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let pairs = match PortRangesConfig::deserialize(deserializer)? {
            PortRangesConfig::Single { start, end } => vec![(start, end)],
            PortRangesConfig::Text(text) => {
                return parse_ranges(&text).map_err(serde::de::Error::custom)
            }
            PortRangesConfig::Pairs(pairs) => pairs,
        };

        if pairs.is_empty() {
            return Err(serde::de::Error::custom("expected at least one port range"));
        }
        if let Some(&(start, end)) = pairs.iter().find(|&&(start, end)| start > end) {
            return Err(serde::de::Error::custom(format!(
                "invalid port range {start}-{end}: start must not be greater than end"
            )));
        }

        Ok(PortRanges(pairs))
    }
}

#[cfg(not(tarpaulin_include))]
/// Parse a single `start-end` token (e.g. "100-200") into `(start, end)`.
/// Returns `None` when the token is malformed, cannot be parsed as `u16`,
/// or `start > end`.
fn parse_range(input: &str) -> Option<(u16, u16)> {
    let mut parts = input.trim().splitn(2, '-').map(str::trim);
    let a = parts.next()?;
    let b = parts.next()?;

    let start = a.parse::<u16>().ok()?;
    let end = b.parse::<u16>().ok()?;

    if start <= end {
        Some((start, end))
    } else {
        None
    }
}
#[cfg(not(tarpaulin_include))]
/// Parse a comma-separated list of `start-end` ranges into `PortRanges`.
///
/// Errors with a helpful message identifying the bad token.
fn parse_ranges(input: &str) -> Result<PortRanges, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("empty input: expected one or more comma-separated 'start-end' pairs".into());
    }

    let ranges_res: Result<Vec<(u16, u16)>, String> = s
        .split(',')
        .map(|token| {
            let t = token.trim();
            parse_range(t).ok_or_else(|| {
                format!(
                    "invalid range token `{}` — expected `start-end` with 0 <= start <= end <= 65535",
                    t
                )
            })
        })
        .collect();

    ranges_res.map(PortRanges)
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

    /// Ranges of ports as comma-separated start-end pairs. Example: 1-500,1000-2500,4000-7000
    #[arg(short, long, conflicts_with = "ports", value_parser = parse_ranges)]
    pub range: Option<PortRanges>,

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
    pub batch_size: usize,

    /// The timeout in milliseconds before a port is assumed to be closed.
    #[arg(short, long, default_value = "1500")]
    pub timeout: u32,

    /// The number of tries before a port is assumed to be closed.
    /// If set to 0, rustscan will correct it to 1.
    #[arg(long, default_value = "1")]
    pub tries: u8,

    /// Automatically increases the Unix file-descriptor limit.
    #[cfg_attr(not(unix), arg(hide = true))]
    #[arg(short, long)]
    pub ulimit: Option<usize>,

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

    /// Also list TCP ports that actively refused the connection (closed).
    /// Closed ports are only printed; scripts are never run against them.
    #[arg(long)]
    pub closed: bool,

    /// Milliseconds to wait after scanning a port (on every address) before
    /// scanning the next one, for slow, low-noise scans. 0 disables the delay.
    #[arg(long, default_value = "0", value_name = "MS")]
    pub interval: u64,
}

#[cfg(not(tarpaulin_include))]
impl Opts {
    pub fn read() -> Self {
        let mut opts = Opts::parse();

        if opts.ports.is_none() && opts.range.is_none() {
            opts.range = Some(PortRanges(vec![(LOWEST_PORT_NUMBER, TOP_PORT_NUMBER)]));
        }

        opts
    }

    /// Validates options whose availability or semantics depend on the
    /// operating system.
    ///
    /// # Errors
    ///
    /// Returns an error when an option is unsupported on the current platform.
    pub fn validate_platform(&self) -> Result<(), String> {
        #[cfg(not(unix))]
        {
            if self.ulimit.is_some() {
                return Err(
                    "--ulimit is only supported on Unix-like operating systems. \
                     On Windows, use --batch-size (-b) to control scan concurrency."
                        .to_owned(),
                );
            }
        }

        Ok(())
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
            command, udp, no_banner, closed, interval
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
            closed: false,
            interval: 0,
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
    range: Option<PortRanges>,
    greppable: Option<bool>,
    accessible: Option<bool>,
    batch_size: Option<usize>,
    timeout: Option<u32>,
    tries: Option<u8>,
    ulimit: Option<usize>,
    resolver: Option<String>,
    scan_order: Option<ScanOrder>,
    command: Option<Vec<String>>,
    scripts: Option<ScriptsRequired>,
    exclude_ports: Option<Vec<u16>>,
    exclude_addresses: Option<Vec<String>>,
    udp: Option<bool>,
    no_banner: Option<bool>,
    closed: Option<bool>,
    interval: Option<u64>,
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
    /// closed = false
    /// interval = 0
    ///
    pub fn read(custom_config_path: Option<PathBuf>) -> Self {
        let mut content = String::new();
        let config_path = custom_config_path.unwrap_or_else(|| {
            // Try the XDG-idiomatic location first, then fall back to legacy
            // paths so existing users keep working unchanged.
            for path in [
                default_config_path(),
                legacy_dot_config_path(),
                old_default_config_path(),
            ] {
                if path.exists() {
                    return path;
                }
            }
            default_config_path()
        });

        if config_path.exists() {
            content = match fs::read_to_string(config_path) {
                Ok(content) => content,
                Err(_) => String::new(),
            }
        }

        let config: Config = match toml::from_str(&content) {
            Ok(config) => config,
            Err(e) => {
                crate::tui::println_safe(format_args!(
                    "Found {e} in configuration file.\nAborting scan.\n"
                ));
                std::process::exit(1);
            }
        };

        config
    }
}

/// Returns the preferred config file path: `$XDG_CONFIG_HOME/rustscan/config.toml`
/// on Linux (with the usual `~/.config` fallback when the variable is unset),
/// and the platform-equivalent `dirs::config_dir()` location on macOS / Windows.
pub fn default_config_path() -> PathBuf {
    let Some(mut config_path) = dirs::config_dir() else {
        panic!("Could not infer config file path.");
    };
    config_path.push("rustscan");
    config_path.push("config.toml");
    config_path
}

/// Returns the transitional `$XDG_CONFIG_HOME/.rustscan.toml` path that older
/// builds wrote to. Kept readable for backwards compatibility.
pub fn legacy_dot_config_path() -> PathBuf {
    let Some(mut config_path) = dirs::config_dir() else {
        panic!("Could not infer config file path.");
    };
    config_path.push(".rustscan.toml");
    config_path
}

/// Returns the deprecated home directory config path used for backwards compatibility.
pub fn old_default_config_path() -> PathBuf {
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

    use super::{Config, Opts, PortRanges, ScanOrder, ScriptsRequired};

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
                no_banner: None,
                closed: Some(false),
                interval: None,
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
    fn parses_explicit_batch_size() {
        let opts = Opts::parse_from(["rustscan", "-a", "127.0.0.1", "-b", "1234"]);

        assert_eq!(opts.batch_size, 1234);
    }

    #[test]
    fn parses_explicit_long_batch_size() {
        let opts = Opts::parse_from(["rustscan", "-a", "127.0.0.1", "--batch-size", "4321"]);

        assert_eq!(opts.batch_size, 4321);
    }

    #[test]
    #[cfg(windows)]
    fn windows_platform_validation_accepts_batch_size() {
        let opts = Opts::parse_from(["rustscan", "-a", "127.0.0.1", "--batch-size", "500"]);

        assert!(opts.validate_platform().is_ok());
        assert_eq!(opts.batch_size, 500);
    }

    #[test]
    #[cfg(windows)]
    fn windows_rejects_ulimit() {
        let opts = Opts::parse_from(["rustscan", "-a", "127.0.0.1", "--ulimit", "5000"]);

        let error = opts
            .validate_platform()
            .expect_err("Windows must reject --ulimit");

        assert!(error.contains("--ulimit"));
        assert!(error.contains("Unix"));
        assert!(error.contains("--batch-size"));
    }

    #[test]
    #[cfg(windows)]
    fn windows_hides_ulimit_from_help() {
        let help = Opts::command().render_long_help().to_string();

        assert!(
            !help.contains("--ulimit"),
            "--ulimit should not be advertised on Windows"
        );
    }

    #[test]
    #[cfg(windows)]
    fn windows_rejects_ulimit_from_config_merge() {
        let mut opts = Opts {
            no_config: false,
            ..Default::default()
        };
        let mut config = Config::default();
        config.ulimit = Some(5_000);

        opts.merge(&config);

        let error = opts
            .validate_platform()
            .expect_err("Windows must reject --ulimit supplied by configuration");

        assert!(error.contains("--ulimit"));
    }

    #[test]
    #[cfg(unix)]
    fn unix_platform_validation_accepts_ulimit() {
        let opts = Opts::parse_from(["rustscan", "-a", "127.0.0.1", "--ulimit", "5000"]);

        assert!(opts.validate_platform().is_ok());
        assert_eq!(opts.ulimit, Some(5_000));
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
        config.range = Some(PortRanges(vec![(1, 1_000)]));
        config.ulimit = Some(1_000);
        config.resolver = Some("1.1.1.1".to_owned());

        opts.merge_optional(&config);

        assert_eq!(opts.range, config.range);
        assert_eq!(opts.ulimit, config.ulimit);
        assert_eq!(opts.resolver, config.resolver);
    }

    #[test]
    fn parses_comma_separated_ranges() {
        let opts = Opts::parse_from([
            "rustscan",
            "-a",
            "127.0.0.1",
            "-r",
            "1-100, 200-300,5000-5100",
        ]);

        assert_eq!(
            opts.range,
            Some(PortRanges(vec![(1, 100), (200, 300), (5_000, 5_100)]))
        );
    }

    #[test]
    fn rejects_malformed_ranges() {
        for range in ["", "300-200", "1-100,", "1-2-3", "a-b", "1-70000"] {
            assert!(
                Opts::try_parse_from(["rustscan", "-a", "127.0.0.1", "-r", range]).is_err(),
                "{:?} should be rejected",
                range
            );
        }
    }

    #[test]
    fn config_range_accepts_legacy_table() {
        let config: Config = toml::from_str("range = { start = 1, end = 1000 }").unwrap();

        assert_eq!(config.range, Some(PortRanges(vec![(1, 1_000)])));
    }

    #[test]
    fn config_range_accepts_string_and_pairs() {
        let expected = Some(PortRanges(vec![(1, 100), (200, 300)]));

        let config: Config = toml::from_str("range = \"1-100,200-300\"").unwrap();
        assert_eq!(config.range, expected);

        let config: Config = toml::from_str("range = [[1, 100], [200, 300]]").unwrap();
        assert_eq!(config.range, expected);
    }

    #[test]
    fn config_range_rejects_invalid_ranges() {
        for range in [
            "range = { start = 10, end = 1 }",
            "range = [[10, 1]]",
            "range = []",
            "range = \"10-1\"",
        ] {
            assert!(
                toml::from_str::<Config>(range).is_err(),
                "{:?} should be rejected",
                range
            );
        }
    }

    #[test]
    fn parses_interval_in_milliseconds() {
        let opts = Opts::parse_from(["rustscan", "-a", "127.0.0.1", "--interval", "250"]);
        assert_eq!(opts.interval, 250);

        let opts = Opts::parse_from(["rustscan", "-a", "127.0.0.1"]);
        assert_eq!(opts.interval, 0);
    }
}
