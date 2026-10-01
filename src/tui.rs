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

/// Terminal User Interface Module for RustScan
/// Defines macros to use
#[macro_export]
macro_rules! warning {
    ($name:expr) => {
        $crate::tui::println_safe(format_args!(
            "{} {}",
            ansi_term::Colour::Red.bold().paint("[!]"),
            $name
        ));
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        // if not greppable then print, otherwise no else statement so do not print.
        if !$greppable {
            if $accessible {
                // Don't print the ascii art
                $crate::tui::println_safe(format_args!("{}", $name));
            } else {
                $crate::tui::println_safe(format_args!(
                    "{} {}",
                    ansi_term::Colour::Red.bold().paint("[!]"),
                    $name
                ));
            }
        }
    };
}

#[macro_export]
macro_rules! detail {
    ($name:expr) => {
        $crate::tui::println_safe(format_args!(
            "{} {}",
            ansi_term::Colour::Blue.bold().paint("[~]"),
            $name
        ));
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        // if not greppable then print, otherwise no else statement so do not print.
        if !$greppable {
            if $accessible {
                // Don't print the ascii art
                $crate::tui::println_safe(format_args!("{}", $name));
            } else {
                $crate::tui::println_safe(format_args!(
                    "{} {}",
                    ansi_term::Colour::Blue.bold().paint("[~]"),
                    $name
                ));
            }
        }
    };
}

#[macro_export]
macro_rules! output {
    ($name:expr) => {
        $crate::tui::println_safe(format_args!(
            "{} {}",
            ansi_term::Colour::RGB(0, 255, 9).bold().paint("[>]"),
            $name
        ));
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        // if not greppable then print, otherwise no else statement so do not print.
        if !$greppable {
            if $accessible {
                // Don't print the ascii art
                $crate::tui::println_safe(format_args!("{}", $name));
            } else {
                $crate::tui::println_safe(format_args!(
                    "{} {}",
                    ansi_term::Colour::RGB(0, 255, 9).bold().paint("[>]"),
                    $name
                ));
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
