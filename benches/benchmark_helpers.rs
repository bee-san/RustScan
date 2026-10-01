use criterion::{criterion_group, criterion_main, Criterion};
use rustscan::generated::get_parsed_data;
use rustscan::input::{Opts, PortRange, ScanOrder};
use rustscan::port_strategy::PortStrategy;
use rustscan::scanner::build_udp_payload_lookup;
use std::collections::BTreeMap;
use std::hint::black_box;
use std::net::IpAddr;
use std::time::Duration;

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

// Replicates the old UDP payload selection behavior:
// scan the whole UDP payload map and find the last payload whose port list contains `port`.
fn old_payload_for_port(udp_map: &'static BTreeMap<Vec<u16>, Vec<u8>>, port: u16) -> &'static [u8] {
    let mut payload: &'static [u8] = b"";
    for (ports, value) in udp_map.iter() {
        if ports.contains(&port) {
            payload = value.as_slice();
        }
    }
    payload
}

fn criterion_benchmark(c: &mut Criterion) {
    // Benching helper functions
    c.bench_function("parse address", |b| b.iter(bench_address));

    c.bench_function("port strategy", |b| b.iter(bench_port_strategy));

    let mut address_group = c.benchmark_group("address parsing");
    address_group.measurement_time(Duration::from_secs(10));
    address_group.bench_function("parse addresses with exclusions", |b| {
        b.iter(bench_address_parsing)
    });
    address_group.finish();

    // UDP payload lookup micro-benchmark: compares the old linear scan of the
    // payload map with the precomputed port -> payload lookup. No sockets.
    let udp_map = get_parsed_data();
    let lookup = build_udp_payload_lookup(udp_map);
    let ports: Vec<u16> = (1..=4096).collect();

    c.bench_function("udp payload lookup/old scan map 1..4096", |b| {
        b.iter(|| {
            for &p in ports.iter() {
                let payload = old_payload_for_port(black_box(udp_map), black_box(p));
                black_box(payload);
            }
        })
    });

    c.bench_function("udp payload lookup/new hashmap 1..4096", |b| {
        b.iter(|| {
            for &p in ports.iter() {
                let payload = lookup.get(&p).copied().unwrap_or(b"");
                black_box(payload);
            }
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
