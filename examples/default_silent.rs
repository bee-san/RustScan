/// Example that verifies the library is silent by default.
/// Does NOT call enable_output() — all output macros should produce
/// nothing on stdout. Built and spawned by the integration test in
/// tests/stdout_suppression.rs.
fn main() {
    // Do NOT call enable_output() — library must be silent by default.
    rustscan::warning!("DEFAULT_SILENT_WARNING");
    rustscan::detail!("DEFAULT_SILENT_DETAIL");
    rustscan::output!("DEFAULT_SILENT_OUTPUT");
}
