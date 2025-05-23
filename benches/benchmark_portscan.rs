use async_std::task::block_on;
use criterion::{criterion_group, criterion_main, Criterion};
use rustscan::input::{Opts, PortRange, ScanOrder};
use rustscan::port_strategy::PortStrategy;
use rustscan::scanner::Scanner;
use std::hint::black_box;
use std::net::IpAddr;
use std::time::Duration;

fn portscan_tcp(scanner: &Scanner) {
    let _scan_result = block_on(scanner.run());
}

fn portscan_udp(scanner: &Scanner) {
    let _scan_result = block_on(scanner.run());
}

fn bench_address() {
    let _addrs = ["127.0.0.1".parse::<IpAddr>().unwrap()];
}

fn bench_port_strategy() {
    let range = PortRange {
        start: 1,
        end: 1_000,
    };
    let _strategy = PortStrategy::pick(&Some(range.clone()), None, ScanOrder::Serial);
}

fn bench_address_parsing() {
    let opts = Opts {
        addresses: vec![
            "127.0.0.1".to_owned(),
            "10.2.0.1".to_owned(),
            "192.168.0.0/24".to_owned(),
        ],
        exclude_addresses: Some(vec![
            "10.0.0.0/8".to_owned(),
            "172.16.0.0/12".to_owned(),
            "192.168.0.0/16".to_owned(),
            "172.16.0.1".to_owned(),
        ]),
        ..Default::default()
    };
    let _ips = rustscan::address::parse_addresses(&opts);
}

fn criterion_benchmark(c: &mut Criterion) {
    let addrs = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
    let range = PortRange {
        start: 1,
        end: 1_000,
    };
    let strategy_tcp = PortStrategy::pick(&Some(range.clone()), None, ScanOrder::Serial);
    let strategy_udp = PortStrategy::pick(&Some(range.clone()), None, ScanOrder::Serial);

    let scanner_tcp = Scanner::new(
        &addrs,
        10,
        Duration::from_millis(10),
        1,
        false,
        strategy_tcp,
        true,
        vec![],
        false,
    );

    c.bench_function("portscan tcp", |b| {
        b.iter(|| portscan_tcp(black_box(&scanner_tcp)))
    });

    let scanner_udp = Scanner::new(
        &addrs,
        10,
        Duration::from_millis(10),
        1,
        false,
        strategy_udp,
        true,
        vec![],
        true,
    );

    let mut udp_group = c.benchmark_group("portscan udp");
    udp_group.measurement_time(Duration::from_secs(20));
    udp_group.bench_function("portscan udp", |b| {
        b.iter(|| portscan_udp(black_box(&scanner_udp)))
    });
    udp_group.finish();

    // Benching helper functions
    c.bench_function("parse address", |b| b.iter(bench_address));

    c.bench_function("port strategy", |b| b.iter(bench_port_strategy));

    let mut address_group = c.benchmark_group("address parsing");
    address_group.measurement_time(Duration::from_secs(10));
    address_group.bench_function("parse addresses with exclusions", |b| {
        b.iter(|| bench_address_parsing())
    });
    address_group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
