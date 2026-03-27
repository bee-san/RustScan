use rustscan::generated::get_parsed_data;
use rustscan::scanner::build_udp_payload_lookup;

#[test]
fn udp_payload_lookup_contains_common_udp_ports() {
    let udp_map = get_parsed_data();
    let lookup = build_udp_payload_lookup(udp_map);

    // These are common UDP services; the payload database should include them.
    assert!(
        lookup.contains_key(&53),
        "expected UDP payload for DNS (53)"
    );
    assert!(
        lookup.contains_key(&123),
        "expected UDP payload for NTP (123)"
    );
}

#[test]
fn udp_payload_lookup_payloads_are_non_empty_for_known_ports() {
    let udp_map = get_parsed_data();
    let lookup = build_udp_payload_lookup(udp_map);

    // Don't assert exact bytes (the generated payload set may evolve),
    // but it should not be empty for these well-known protocols.
    let dns = lookup.get(&53).expect("missing DNS payload");
    assert!(!dns.is_empty(), "DNS payload should not be empty");

    let ntp = lookup.get(&123).expect("missing NTP payload");
    assert!(!ntp.is_empty(), "NTP payload should not be empty");
}
