use std::fs;

#[test]
fn cross_config_includes_aarch64_target() {
    let cross_toml = fs::read_to_string("Cross.toml").expect("Cross.toml should exist");
    assert!(
        cross_toml.contains("[target.aarch64-unknown-linux-gnu]"),
        "Cross.toml must define target.aarch64-unknown-linux-gnu"
    );
    assert!(
        cross_toml.contains("pre-build"),
        "Cross.toml must define pre-build steps for aarch64 target"
    );
}
