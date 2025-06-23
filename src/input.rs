//! Provides a means to read, parse and hold configuration options for scans.
use clap::{Parser, ValueEnum};
use serde_derive::Deserialize;
use std::fs;
use std::path::PathBuf;

const LOWEST_PORT_NUMBER: u16 = 1;
const TOP_PORT_NUMBER: u16 = 65535;

// https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default
const TOP_1000_PORTS: [u16; 1000] = [
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70,
    79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139,
    143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311,
    340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512,
    513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636,
    646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783,
    787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992,
    993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026,
    1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042,
    1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058,
    1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074,
    1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090,
    1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108,
    1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137,
    1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175,
    1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244,
    1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334,
    1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580,
    1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755,
    1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947,
    1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
    2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046,
    2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135,
    2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366,
    2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605,
    2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910,
    2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052,
    3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323,
    3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527,
    3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827,
    3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998,
    4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321,
    4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002,
    5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120,
    5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440,
    5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801,
    5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906,
    5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989,
    5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106,
    6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666,
    6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001,
    7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512,
    7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002,
    8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085,
    8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254,
    8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701,
    8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080,
    9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415, 9418,
    9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900,
    9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010,
    10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628,
    10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783,
    14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012,
    16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283,
    19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939,
    23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715, 28201,
    30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775,
    32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571,
    34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100,
    48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165,
    49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500,
    50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555,
    55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623,
    64680, 65000, 65129, 65389,
];

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

pub type Ports = Vec<u16>;

#[cfg(not(tarpaulin_include))]
pub fn parse_ports_and_ranges(input: &str) -> Result<Ports, String> {
    let mut ports = Vec::new();

    for part in input.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if part.contains('-') {
            let range_ports = parse_port_range(part)?;
            ports.extend(range_ports);
        } else {
            let port = parse_single_port(part)?;
            ports.push(port);
        }
    }

    if ports.is_empty() {
        return Err(String::from("No valid ports or ranges provided"));
    }

    ports.sort_unstable();
    ports.dedup();

    Ok(ports)
}

fn parse_port_range(range_str: &str) -> Result<Vec<u16>, String> {
    let range_parts: Vec<&str> = range_str.split('-').collect();
    if range_parts.len() != 2 {
        return Err(format!(
            "Invalid range format '{range_str}'. Expected 'start-end'. Example: 1-1000.",
        ));
    }

    let start: u16 = range_parts[0].parse().map_err(|_| {
        format!(
            "Invalid start port '{}' in range '{range_str}'",
            range_parts[0]
        )
    })?;
    let end: u16 = range_parts[1].parse().map_err(|_| {
        format!(
            "Invalid end port '{}' in range '{range_str}'",
            range_parts[1]
        )
    })?;

    if start > end {
        return Err(format!(
            "Start port {start} is greater than end port {end} in range '{range_str}'",
        ));
    }

    if start < LOWEST_PORT_NUMBER {
        return Err(format!(
            "Ports in range '{range_str}' must be between {LOWEST_PORT_NUMBER} and {TOP_PORT_NUMBER}",
        ));
    }

    Ok((start..=end).collect())
}

fn parse_single_port(port_str: &str) -> Result<u16, String> {
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("Invalid port number '{port_str}'"))?;

    if port < LOWEST_PORT_NUMBER {
        return Err(format!(
            "Port {port} must be between {LOWEST_PORT_NUMBER} and {TOP_PORT_NUMBER}",
        ));
    }

    Ok(port)
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

    /// A list of ports and/or port ranges to be scanned. Examples: 80,443,8080 or 1-1000 or 1-1000,8080
    #[arg(short, long, alias = "range", value_parser = parse_ports_and_ranges, conflicts_with = "top")]
    pub ports: Option<Ports>,

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

        if opts.ports.is_none() {
            opts.ports = Some((LOWEST_PORT_NUMBER..=TOP_PORT_NUMBER).collect());
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
        if self.top {
            self.ports = Some(TOP_1000_PORTS.to_vec());
        } else if config.ports.is_some() {
            self.ports = config.ports.clone();
        }

        merge_optional!(resolver, ulimit, exclude_ports, exclude_addresses);
    }
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            addresses: vec![],
            ports: None,
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

    use super::{parse_ports_and_ranges, Config, Opts, ScanOrder, ScriptsRequired};

    impl Config {
        fn default() -> Self {
            Self {
                addresses: Some(vec!["127.0.0.1".to_owned()]),
                ports: None,
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
        config.ports = Some((1..=1000).collect::<Vec<u16>>());
        config.ulimit = Some(1_000);
        config.resolver = Some("1.1.1.1".to_owned());

        opts.merge_optional(&config);

        assert_eq!(opts.ports, Some((1..=1000).collect::<Vec<u16>>()));
        assert_eq!(opts.ulimit, config.ulimit);
        assert_eq!(opts.resolver, config.resolver);
    }

    #[test]
    fn test_parse_ports_and_ranges_single_port() {
        let result = parse_ports_and_ranges("80");
        assert_eq!(result, Ok(vec![80]));
    }

    #[test]
    fn test_parse_ports_and_ranges_multiple_ports() {
        let result = parse_ports_and_ranges("80,443,8080");
        assert_eq!(result, Ok(vec![80, 443, 8080]));
    }

    #[test]
    fn test_parse_ports_and_ranges_single_range() {
        let result = parse_ports_and_ranges("1-5");
        assert_eq!(result, Ok(vec![1, 2, 3, 4, 5]));
    }

    #[test]
    fn test_parse_ports_and_ranges_mixed_ports_and_ranges() {
        let result = parse_ports_and_ranges("80,443,1-3,8080");
        assert_eq!(result, Ok(vec![1, 2, 3, 80, 443, 8080]));
    }

    #[test]
    fn test_parse_ports_and_ranges_with_spaces() {
        let result = parse_ports_and_ranges("80, 443, 1-3, 8080");
        assert_eq!(result, Ok(vec![1, 2, 3, 80, 443, 8080]));
    }

    #[test]
    fn test_parse_ports_and_ranges_duplicates() {
        let result = parse_ports_and_ranges("80,443,80,443");
        assert_eq!(result, Ok(vec![80, 443]));
    }

    #[test]
    fn test_parse_ports_and_ranges_empty_input() {
        let result = parse_ports_and_ranges("");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("No valid ports or ranges provided"));
    }

    #[test]
    fn test_parse_ports_and_ranges_invalid_port() {
        let result = parse_ports_and_ranges("80,abc,443");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid port number 'abc'"));
    }

    #[test]
    fn test_parse_ports_and_ranges_invalid_range() {
        let result = parse_ports_and_ranges("80,1-abc,443");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Invalid end port 'abc' in range '1-abc'"));
    }

    #[test]
    fn test_parse_ports_and_ranges_invalid_range_format() {
        let result = parse_ports_and_ranges("80,1-2-3,443");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Invalid range format '1-2-3'. Expected 'start-end'"));
    }

    #[test]
    fn test_parse_ports_and_ranges_reverse_range() {
        let result = parse_ports_and_ranges("80,5-1,443");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Start port 5 is greater than end port 1 in range '5-1'"));
    }

    #[test]
    fn test_parse_ports_and_ranges_out_of_bounds_port() {
        let result = parse_ports_and_ranges("80,70000,443");
        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        println!("Actual error message: {}", error_msg);
        assert!(error_msg.contains("Invalid port number '70000'"));
    }

    #[test]
    fn test_parse_ports_and_ranges_out_of_bounds_range() {
        let result = parse_ports_and_ranges("80,1-70000,443");
        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        println!("Actual error message: {}", error_msg);
        assert!(error_msg.contains("Invalid end port '70000' in range '1-70000'"));
    }

    #[test]
    fn test_parse_ports_and_ranges_zero_port() {
        let result = parse_ports_and_ranges("80,0,443");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Port 0 must be between 1 and 65535"));
    }

    #[test]
    fn test_parse_ports_and_ranges_complex_mixed() {
        let result = parse_ports_and_ranges("1,80,443,1-5,8080,9090,10-12");
        assert_eq!(
            result,
            Ok(vec![1, 2, 3, 4, 5, 10, 11, 12, 80, 443, 8080, 9090])
        );
    }
}
