//! Utilities for terminal output during scanning.

use std::io::Write;

/// Prints a single line to stdout without ever panicking.
///
/// `println!` panics when writing to stdout fails, which is fatal under the
/// `panic = "abort"` release profile. That includes the `BrokenPipe` error
/// produced when a downstream consumer (e.g. `rustscan -g ... | head`)
/// closes the pipe, so instead the process exits quietly when that happens.
/// Other output errors are reported on stderr before exiting.
///
/// All user-facing output should go through this function (the `warning!`,
/// `detail!`, `output!` and `funny_opening!` macros already do) instead of
/// `println!`.
pub fn println_safe(args: std::fmt::Arguments<'_>) {
    match writeln!(std::io::stdout().lock(), "{args}") {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
            // the reader end of the pipe is gone; nothing left to print to
            std::process::exit(0);
        }
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "rustscan: failed writing to stdout: {e}");
            std::process::exit(1);
        }
    }
}

/// Whether colored output is enabled.
///
/// Honors the `NO_COLOR` convention (<https://no-color.org>): when the
/// variable is present and non-empty, colors are disabled. This keeps the
/// banner and status tags readable on light terminal themes and for tools
/// that cannot parse escape codes (see issue #778).
///
/// The environment is read on every call so embedders never observe stale
/// state; output paths are cold enough that the lookup cost does not matter.
pub fn colors_enabled() -> bool {
    colors_enabled_for(std::env::var_os("NO_COLOR").as_deref())
}

/// Pure form of [`colors_enabled`] over the variable's value, for tests.
///
/// `None` (unset) and `Some("")` (empty) both mean colors stay on; any other
/// value disables them.
fn colors_enabled_for(no_color: Option<&std::ffi::OsStr>) -> bool {
    no_color.is_none_or(|value| value.is_empty())
}

/// Prints one of two pre-rendered lines depending on `NO_COLOR`.
///
/// For call sites like the startup banner where the colored and plain
/// renderings differ by more than a tag.
pub fn print_colored_or_plain(colored: impl std::fmt::Display, plain: impl std::fmt::Display) {
    if colors_enabled() {
        println_safe(format_args!("{colored}"));
    } else {
        println_safe(format_args!("{plain}"));
    }
}

/// Prints `tag name`, colored unless `NO_COLOR` is set.
///
/// Shared by the status macros below.
pub fn print_tagged(
    painted_tag: impl std::fmt::Display,
    plain_tag: &str,
    name: impl std::fmt::Display,
) {
    if colors_enabled() {
        println_safe(format_args!("{painted_tag} {name}"));
    } else {
        // NO_COLOR: keep the tag, drop the escape codes.
        println_safe(format_args!("{plain_tag} {name}"));
    }
}

/// Terminal User Interface Module for RustScan
/// Defines macros to use
#[macro_export]
macro_rules! warning {
    ($name:expr) => {
        $crate::tui::print_tagged(ansi_term::Colour::Red.bold().paint("[!]"), "[!]", $name);
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        // if not greppable then print, otherwise no else statement so do not print.
        if !$greppable {
            if $accessible {
                // Don't print the ascii art
                $crate::tui::println_safe(format_args!("{}", $name));
            } else {
                $crate::tui::print_tagged(ansi_term::Colour::Red.bold().paint("[!]"), "[!]", $name);
            }
        }
    };
}

#[macro_export]
macro_rules! detail {
    ($name:expr) => {
        $crate::tui::print_tagged(ansi_term::Colour::Blue.bold().paint("[~]"), "[~]", $name);
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        // if not greppable then print, otherwise no else statement so do not print.
        if !$greppable {
            if $accessible {
                // Don't print the ascii art
                $crate::tui::println_safe(format_args!("{}", $name));
            } else {
                $crate::tui::print_tagged(
                    ansi_term::Colour::Blue.bold().paint("[~]"),
                    "[~]",
                    $name,
                );
            }
        }
    };
}

#[macro_export]
macro_rules! output {
    ($name:expr) => {
        $crate::tui::print_tagged(
            ansi_term::Colour::RGB(0, 255, 9).bold().paint("[>]"),
            "[>]",
            $name,
        );
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        // if not greppable then print, otherwise no else statement so do not print.
        if !$greppable {
            if $accessible {
                // Don't print the ascii art
                $crate::tui::println_safe(format_args!("{}", $name));
            } else {
                $crate::tui::print_tagged(
                    ansi_term::Colour::RGB(0, 255, 9).bold().paint("[>]"),
                    "[>]",
                    $name,
                );
            }
        }
    };
}

#[macro_export]
macro_rules! funny_opening {
    // prints a funny quote / opening
    () => {
        use rand::seq::IndexedRandom;
        let quotes = vec![
            "Nmap? More like slowmap.🐢",
            "🌍HACK THE PLANET🌍",
            "Real hackers hack time ⌛",
            "Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan",
            "😵 https://admin.tryhackme.com",
            "0day was here ♥",
            "I don't always scan ports, but when I do, I prefer RustScan.",
            "RustScan: Where scanning meets swagging. 😎",
            "To scan or not to scan? That is the question.",
            "RustScan: Because guessing isn't hacking.",
            "Scanning ports like it's my full-time job. Wait, it is.",
            "Open ports, closed hearts.",
            "I scanned my computer so many times, it thinks we're dating.",
            "Port scanning: Making networking exciting since... whenever.",
            "You miss 100% of the ports you don't scan. - RustScan",
            "Breaking and entering... into the world of open ports.",
            "TCP handshake? More like a friendly high-five!",
            "Scanning ports: The virtual equivalent of knocking on doors.",
            "RustScan: Making sure 'closed' isn't just a state of mind.",
            "RustScan: allowing you to send UDP packets into the void 1200x faster than NMAP",
            "Port scanning: Because every port has a story to tell.",
            "I scanned ports so fast, even my computer was surprised.",
            "Scanning ports faster than you can say 'SYN ACK'",
            "RustScan: Where '404 Not Found' meets '200 OK'.",
            "RustScan: Exploring the digital landscape, one IP at a time.",
            "TreadStone was here 🚀",
            "With RustScan, I scan ports so fast, even my firewall gets whiplash 💨",
            "Scanning ports so fast, even the internet got a speeding ticket!",
        ];
        let random_quote = quotes.choose(&mut rand::rng()).unwrap();

        $crate::tui::println_safe(format_args!("{}\n", random_quote));
    };
}

#[cfg(test)]
mod tests {
    use super::colors_enabled_for;
    use std::ffi::OsStr;

    // `colors_enabled` itself reads the process environment, which parallel
    // tests cannot safely mutate, so only the pure helper is tested here.

    #[test]
    fn colors_stay_on_when_no_color_is_unset_or_empty() {
        assert!(colors_enabled_for(None));
        assert!(colors_enabled_for(Some(OsStr::new(""))));
    }

    #[test]
    fn colors_turn_off_when_no_color_has_any_value() {
        for value in ["1", "true", "0", " "] {
            assert!(
                !colors_enabled_for(Some(OsStr::new(value))),
                "NO_COLOR={:?} should disable colors",
                value
            );
        }
    }
}
