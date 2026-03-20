//! Multi-site folder scan functionality.
//!
//! Reads a folder of .txt files (one per site), scans each site's IPs,
//! and produces per-site and overall reports.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::executor::block_on;

use crate::address::parse_addresses;
use crate::input::{Opts, ScriptsRequired};
use crate::port_strategy::PortStrategy;
use crate::scanner::Scanner;
use crate::{detail, output, warning};

/// Results for a single site scan.
pub struct SiteResult {
    pub site_name: String,
    pub ips_scanned: Vec<IpAddr>,
    pub ports_per_ip: HashMap<IpAddr, Vec<u16>>,
}

impl SiteResult {
    pub fn total_open_ports(&self) -> usize {
        self.ports_per_ip.values().map(|ports| ports.len()).sum()
    }

    pub fn systems_with_open_ports(&self) -> usize {
        self.ports_per_ip.len()
    }

    /// Returns a sorted set of unique port numbers found for this site.
    pub fn unique_services(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self.ports_per_ip.values().flatten().copied().collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }
}

/// Aggregated results across all sites.
pub struct OverallReport {
    pub site_results: Vec<SiteResult>,
}

impl OverallReport {
    pub fn total_systems_scanned(&self) -> usize {
        self.site_results.iter().map(|r| r.ips_scanned.len()).sum()
    }

    pub fn total_systems_with_open_ports(&self) -> usize {
        self.site_results
            .iter()
            .map(|r| r.systems_with_open_ports())
            .sum()
    }

    pub fn total_open_ports(&self) -> usize {
        self.site_results.iter().map(|r| r.total_open_ports()).sum()
    }

    /// Returns a sorted set of unique port numbers across all sites.
    pub fn unique_services(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self
            .site_results
            .iter()
            .flat_map(|r| r.unique_services())
            .collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }
}

/// Reads all .txt files from a folder, returns (site_name, file_path) sorted alphabetically.
pub fn discover_sites(folder: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    if !folder.is_dir() {
        return Err(format!("{:?} is not a directory", folder));
    }

    let entries = fs::read_dir(folder).map_err(|e| format!("Cannot read directory: {e}"))?;

    let mut sites: Vec<(String, PathBuf)> = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext.eq_ignore_ascii_case("txt") {
                    if let Some(stem) = path.file_stem() {
                        let site_name = stem.to_string_lossy().to_string();
                        sites.push((site_name, path));
                    }
                }
            }
        }
    }

    sites.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));

    if sites.is_empty() {
        return Err(format!("No .txt files found in {:?}", folder));
    }

    Ok(sites)
}

/// Scans a single site: reads IPs from file, runs scanner, returns SiteResult.
pub fn scan_site(site_name: &str, file_path: &Path, opts: &Opts, batch_size: usize) -> SiteResult {
    let mut site_opts = opts.clone();
    site_opts.addresses = vec![file_path.to_string_lossy().to_string()];

    let ips = parse_addresses(&site_opts);

    if ips.is_empty() {
        warning!(
            format!(
                "Site '{}': No valid IPs found in {:?}",
                site_name, file_path
            ),
            opts.greppable,
            opts.accessible
        );
        return SiteResult {
            site_name: site_name.to_string(),
            ips_scanned: Vec::new(),
            ports_per_ip: HashMap::new(),
        };
    }

    detail!(
        format!("Site '{}': Scanning {} systems...", site_name, ips.len()),
        opts.greppable,
        opts.accessible
    );

    let scanner = Scanner::new(
        &ips,
        batch_size,
        Duration::from_millis(opts.timeout.into()),
        opts.tries,
        opts.greppable,
        PortStrategy::pick(&opts.range, opts.ports.clone(), opts.scan_order),
        opts.accessible,
        opts.exclude_ports.clone().unwrap_or_default(),
        opts.udp,
    );

    let scan_result = block_on(scanner.run());

    let mut ports_per_ip: HashMap<IpAddr, Vec<u16>> = HashMap::new();
    for socket in scan_result {
        ports_per_ip
            .entry(socket.ip())
            .or_insert_with(Vec::new)
            .push(socket.port());
    }

    // Sort ports for consistent output
    for ports in ports_per_ip.values_mut() {
        ports.sort_unstable();
    }

    SiteResult {
        site_name: site_name.to_string(),
        ips_scanned: ips,
        ports_per_ip,
    }
}

/// Writes per-site result to a file and prints summary to stdout.
pub fn export_site_result(
    result: &SiteResult,
    output_dir: &Path,
    greppable: bool,
    accessible: bool,
) {
    // Print to stdout
    println!();
    output!(
        format!(
            "Site '{}': {} systems scanned, {} with open ports, {} open ports found",
            result.site_name,
            result.ips_scanned.len(),
            result.systems_with_open_ports(),
            result.total_open_ports()
        ),
        greppable,
        accessible
    );

    for (ip, ports) in &result.ports_per_ip {
        let ports_str: Vec<String> = ports.iter().map(ToString::to_string).collect();
        println!("{} -> [{}]", ip, ports_str.join(","));
    }

    // Write to file
    if let Err(e) = fs::create_dir_all(output_dir) {
        warning!(
            format!("Could not create output directory: {e}"),
            greppable,
            accessible
        );
        return;
    }

    let file_path = output_dir.join(format!("{}_results.txt", result.site_name));
    let mut content = String::new();

    content.push_str(&format!("Site: {}\n", result.site_name));
    content.push_str(&format!("Systems scanned: {}\n", result.ips_scanned.len()));
    content.push_str(&format!(
        "Systems with open ports: {}\n",
        result.systems_with_open_ports()
    ));
    content.push_str(&format!(
        "Total open ports: {}\n",
        result.total_open_ports()
    ));

    let services = result.unique_services();
    if !services.is_empty() {
        let services_str: Vec<String> = services.iter().map(ToString::to_string).collect();
        content.push_str(&format!("Services (ports): {}\n", services_str.join(",")));
    }

    content.push('\n');

    for (ip, ports) in &result.ports_per_ip {
        let ports_str: Vec<String> = ports.iter().map(ToString::to_string).collect();
        content.push_str(&format!("{} -> [{}]\n", ip, ports_str.join(",")));
    }

    match fs::File::create(&file_path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(content.as_bytes()) {
                warning!(
                    format!("Could not write site result file: {e}"),
                    greppable,
                    accessible
                );
            } else {
                detail!(
                    format!("Site results written to {:?}", file_path),
                    greppable,
                    accessible
                );
            }
        }
        Err(e) => {
            warning!(
                format!("Could not create site result file: {e}"),
                greppable,
                accessible
            );
        }
    }
}

/// Generates and writes the overall summary report.
pub fn export_overall_report(
    report: &OverallReport,
    output_dir: &Path,
    greppable: bool,
    accessible: bool,
) {
    let unique_services = report.unique_services();
    let unique_services_str: Vec<String> =
        unique_services.iter().map(ToString::to_string).collect();

    // Print to stdout
    println!();
    println!("====== MULTI-SITE SCAN REPORT ======");
    println!("Total sites scanned: {}", report.site_results.len());
    println!("Total systems scanned: {}", report.total_systems_scanned());
    println!(
        "Systems with open ports: {}",
        report.total_systems_with_open_ports()
    );
    println!("Total open ports found: {}", report.total_open_ports());
    println!("Unique services (ports): {}", unique_services.len());
    if !unique_services.is_empty() {
        println!("Services: {}", unique_services_str.join(","));
    }
    println!();
    println!("--- Per Site Summary ---");

    for result in &report.site_results {
        let site_services = result.unique_services();
        let site_services_str: Vec<String> =
            site_services.iter().map(ToString::to_string).collect();
        println!(
            "{}: {} systems scanned, {} with open ports, {} open ports, services: [{}]",
            result.site_name,
            result.ips_scanned.len(),
            result.systems_with_open_ports(),
            result.total_open_ports(),
            site_services_str.join(",")
        );
    }
    println!("=====================================");

    // Write to file
    if let Err(e) = fs::create_dir_all(output_dir) {
        warning!(
            format!("Could not create output directory: {e}"),
            greppable,
            accessible
        );
        return;
    }

    let file_path = output_dir.join("overall_report.txt");
    let mut content = String::new();

    content.push_str("====== MULTI-SITE SCAN REPORT ======\n");
    content.push_str(&format!(
        "Total sites scanned: {}\n",
        report.site_results.len()
    ));
    content.push_str(&format!(
        "Total systems scanned: {}\n",
        report.total_systems_scanned()
    ));
    content.push_str(&format!(
        "Systems with open ports: {}\n",
        report.total_systems_with_open_ports()
    ));
    content.push_str(&format!(
        "Total open ports found: {}\n",
        report.total_open_ports()
    ));
    content.push_str(&format!(
        "Unique services (ports): {}\n",
        unique_services.len()
    ));
    if !unique_services.is_empty() {
        content.push_str(&format!("Services: {}\n", unique_services_str.join(",")));
    }
    content.push('\n');

    content.push_str("--- Per Site Summary ---\n");
    for result in &report.site_results {
        let site_services = result.unique_services();
        let site_services_str: Vec<String> =
            site_services.iter().map(ToString::to_string).collect();
        content.push_str(&format!(
            "{}: {} systems scanned, {} with open ports, {} open ports, services: [{}]\n",
            result.site_name,
            result.ips_scanned.len(),
            result.systems_with_open_ports(),
            result.total_open_ports(),
            site_services_str.join(",")
        ));
    }
    content.push_str("=====================================\n");

    // Append per-site details
    content.push('\n');
    for result in &report.site_results {
        content.push_str(&format!("\n--- Site: {} ---\n", result.site_name));
        for (ip, ports) in &result.ports_per_ip {
            let ports_str: Vec<String> = ports.iter().map(ToString::to_string).collect();
            content.push_str(&format!("{} -> [{}]\n", ip, ports_str.join(",")));
        }
    }

    match fs::File::create(&file_path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(content.as_bytes()) {
                warning!(
                    format!("Could not write overall report: {e}"),
                    greppable,
                    accessible
                );
            } else {
                output!(
                    format!("Overall report written to {:?}", file_path),
                    greppable,
                    accessible
                );
            }
        }
        Err(e) => {
            warning!(
                format!("Could not create overall report file: {e}"),
                greppable,
                accessible
            );
        }
    }
}

/// Main entry point for folder scan mode.
pub fn run_folder_scan(opts: &Opts, batch_size: usize) {
    let folder = opts.folder.as_ref().unwrap();

    let sites = match discover_sites(folder) {
        Ok(sites) => sites,
        Err(e) => {
            warning!(format!("{e}"), opts.greppable, opts.accessible);
            std::process::exit(1);
        }
    };

    output!(
        format!(
            "Multi-site scan: found {} site(s) in {:?}",
            sites.len(),
            folder
        ),
        opts.greppable,
        opts.accessible
    );

    for (name, _) in &sites {
        detail!(format!("  - {}", name), opts.greppable, opts.accessible);
    }

    let mut all_results = Vec::new();

    for (site_name, file_path) in &sites {
        println!();
        output!(
            format!("=== Scanning site: {} ===", site_name),
            opts.greppable,
            opts.accessible
        );

        let result = scan_site(site_name, file_path, opts, batch_size);
        export_site_result(&result, &opts.output_dir, opts.greppable, opts.accessible);

        // Run scripts per IP if configured
        if !opts.greppable && opts.scripts != ScriptsRequired::None {
            run_scripts_for_site(&result, opts);
        }

        all_results.push(result);
    }

    let report = OverallReport {
        site_results: all_results,
    };
    export_overall_report(&report, &opts.output_dir, opts.greppable, opts.accessible);
}

/// Runs configured scripts for each IP in a site result.
fn run_scripts_for_site(result: &SiteResult, opts: &Opts) {
    use crate::scripts::{init_scripts, Script};

    let scripts_to_run = match init_scripts(&opts.scripts) {
        Ok(scripts) => scripts,
        Err(e) => {
            warning!(
                format!("Script init failed for site '{}': {e}", result.site_name),
                opts.greppable,
                opts.accessible
            );
            return;
        }
    };

    for (ip, ports) in &result.ports_per_ip {
        for mut script_f in scripts_to_run.clone() {
            if !opts.command.is_empty() {
                let user_extra_args = &opts.command.join(" ");
                if script_f.call_format.is_some() {
                    let mut call_f = script_f.call_format.unwrap();
                    call_f.push(' ');
                    call_f.push_str(user_extra_args);
                    script_f.call_format = Some(call_f);
                }
            }

            let script = Script::build(
                script_f.path,
                *ip,
                ports.clone(),
                script_f.port,
                script_f.ports_separator,
                script_f.tags,
                script_f.call_format,
            );
            match script.run() {
                Ok(script_result) => {
                    detail!(script_result.clone(), opts.greppable, opts.accessible);
                }
                Err(e) => {
                    warning!(&format!("Error {e}"), opts.greppable, opts.accessible);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_site_result_counts() {
        let mut ports_per_ip = HashMap::new();
        ports_per_ip.insert("192.168.1.1".parse::<IpAddr>().unwrap(), vec![22, 80, 443]);
        ports_per_ip.insert("192.168.1.2".parse::<IpAddr>().unwrap(), vec![22]);

        let result = SiteResult {
            site_name: "TestSite".to_string(),
            ips_scanned: vec![
                "192.168.1.1".parse().unwrap(),
                "192.168.1.2".parse().unwrap(),
                "192.168.1.3".parse().unwrap(),
            ],
            ports_per_ip,
        };

        assert_eq!(result.total_open_ports(), 4);
        assert_eq!(result.systems_with_open_ports(), 2);
        assert_eq!(result.unique_services(), vec![22, 80, 443]);
    }

    #[test]
    fn test_overall_report_aggregation() {
        let mut ports1 = HashMap::new();
        ports1.insert("10.0.0.1".parse::<IpAddr>().unwrap(), vec![80, 443]);

        let mut ports2 = HashMap::new();
        ports2.insert("10.0.1.1".parse::<IpAddr>().unwrap(), vec![22, 80]);

        let report = OverallReport {
            site_results: vec![
                SiteResult {
                    site_name: "SiteA".to_string(),
                    ips_scanned: vec!["10.0.0.1".parse().unwrap()],
                    ports_per_ip: ports1,
                },
                SiteResult {
                    site_name: "SiteB".to_string(),
                    ips_scanned: vec!["10.0.1.1".parse().unwrap()],
                    ports_per_ip: ports2,
                },
            ],
        };

        assert_eq!(report.total_systems_scanned(), 2);
        assert_eq!(report.total_systems_with_open_ports(), 2);
        assert_eq!(report.total_open_ports(), 4);
        assert_eq!(report.unique_services(), vec![22, 80, 443]);
    }

    #[test]
    fn test_discover_sites() {
        let test_dir = PathBuf::from("/tmp/rustscan_test_sites");
        let _ = fs::remove_dir_all(&test_dir);
        fs::create_dir_all(&test_dir).unwrap();

        fs::write(test_dir.join("Berlin.txt"), "192.168.1.0/24\n").unwrap();
        fs::write(test_dir.join("Munich.txt"), "10.0.0.1\n10.0.0.2\n").unwrap();
        fs::write(test_dir.join("notes.md"), "not a txt file\n").unwrap();

        let sites = discover_sites(&test_dir).unwrap();
        assert_eq!(sites.len(), 2);
        assert_eq!(sites[0].0, "Berlin");
        assert_eq!(sites[1].0, "Munich");

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_discover_sites_empty() {
        let test_dir = PathBuf::from("/tmp/rustscan_test_empty");
        let _ = fs::remove_dir_all(&test_dir);
        fs::create_dir_all(&test_dir).unwrap();

        let result = discover_sites(&test_dir);
        assert!(result.is_err());

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_discover_sites_not_dir() {
        let result = discover_sites(Path::new("/tmp/nonexistent_dir_12345"));
        assert!(result.is_err());
    }
}
