/// Example that exercises output macros with and without suppress_output().
/// Built and spawned by the integration test in tests/stdout_suppression.rs.
fn main() {
    // Before suppression: these markers should appear in stdout.
    rustscan::warning!("PRE_SUPPRESS_WARNING");
    rustscan::detail!("PRE_SUPPRESS_DETAIL");
    rustscan::output!("PRE_SUPPRESS_OUTPUT");

    // Suppress all further library output.
    rustscan::suppress_output();

    // After suppression: these markers must NOT appear in stdout.
    rustscan::warning!("POST_SUPPRESS_WARNING");
    rustscan::detail!("POST_SUPPRESS_DETAIL");
    rustscan::output!("POST_SUPPRESS_OUTPUT");
}
