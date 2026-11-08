# Design: Interactive TUI Mode for RustScan

Status: draft for discussion (issue #710). No implementation until the
discussion outcome exists.

## 1. Problem, evidence, affected users

RustScan is configured entirely through CLI flags plus a TOML config file.
New users must discover ~20 flags (`--batch-size`, `--ulimit`, `--tries`,
`--scan-order`, `--scripts`, UDP mode, excludes, …) before their first
useful scan, and a mistyped flag or range fails late, after a long scan, or
fails cryptically.

Evidence:

- Issue #710 (2024-12-04, @yrncollo) proposes an interactive mode with input
  forms, flag toggles, a live command preview, and run-or-export actions.
- The repository owner (@bee-san) replied on #710 (2024-12-06): "agreed,
  back in the day we did talk about this. Now Rustscan is a library and the
  CLI just calls the library, no reason we can't design frontends for
  rustscan :)". Maintainer direction is therefore: a TUI as a frontend that
  calls the library.
- Recurring usability issues (#822 "how do I get the first open port",
  #825 proxy confusion, #648 wiki how-tos) show first-run friction is real.

Affected: new interactive users (lowered entry barrier); advanced users are
affected only if the default CLI behavior changes — it must not (see §5).

## 2. Goal and non-goals

Goal: an opt-in interactive mode that lets a user fill in targets, ports,
and common options in a terminal form, preview the equivalent `rustscan`
command, and either run the scan in place (with live progress) or print the
command for manual execution.

Non-goals (explicitly out of scope for this contribution):

- No change to default CLI behavior, flags, config file format, or exit
  codes. Piping and scripting keep working byte-for-byte.
- No new scanning capability (no SYN scan, no proxy support, no scheduling).
  The TUI only drives what the library already does.
- No mouse-only or graphics-dependent UI; keyboard-first, usable over SSH.
- No replacement of `--accessible` output or greppable mode.
- No GUI, web UI, or mobile frontend.

## 3. Options considered

### Option A — Explicit `--interactive` flag, same binary (recommended)

`rustscan --interactive` (plus short flag, e.g. `-i`) opens the form. The
form builds an `Opts`, shows the equivalent command line, and either runs
the scan through the existing `Scanner` API or prints the command and exits.

Trade-offs:

- (+) Zero risk to scripts: nothing launches unless asked. No TTY sniffing.
- (+) Single binary, single release artifact; CI matrix unchanged.
- (+) Natural code shape: a new `src/interactive.rs` frontend next to
  `main.rs`, calling `rustscan::{input, scanner, scripts, address}`.
- (−) New users must discover the flag (mitigated by a hint in `--help`
  and in the "No IPs could be resolved" message).
- (−) Dependency weight (ratatui + crossterm) lands in the default build
  unless feature-gated (see §4).

### Option B — Auto-launch when required inputs are missing

As #710 originally proposes: bare `rustscan` with no addresses opens the
TUI instead of erroring.

Trade-offs:

- (+) Most discoverable for newcomers.
- (−) Dangerous for scripts and CI: bare `rustscan` currently exits 1 with
  "No IPs could be resolved". Hanging on a form instead would break
  automation; gating on "stdin/stdout is a TTY" fixes scripts but adds
  platform-specific detection code and a behavior matrix (TTY × args ×
  `--greppable` × `--accessible`) that must be tested on four CI platforms.
- (−) Conflicts with `--accessible`: a full-screen form is hostile to
  screen readers unless the accessible path explicitly bypasses it.

Verdict: reject as the default; a TTY-gated auto-launch could be a later,
separately discussed follow-up once Option A exists.

### Option C — Separate binary / crate (`rustscan-tui`)

Trade-offs:

- (+) Cleanest dependency isolation; the core binary stays lean.
- (−) Second release artifact across six build jobs (build.yml), second
  install path, and version-skew questions between the binaries.
- (−) More process/review overhead for the same user value as Option A.

Verdict: reject for now; reachable later by moving `src/interactive.rs`
into its own crate without changing the design.

## 4. Recommended option and why

Option A, with two refinements:

1. **Feature gate.** Put the TUI behind a Cargo feature (`tui`, default-on
   for interactive installs, `--no-default-features` for minimal builds).
   This bounds the dependency risk (musl/static, Windows, supply chain)
   while keeping one binary. Exact default (on/off) is open question Q1.
2. **Explicit module name.** `src/tui.rs` already exists and means "output
   macros", not a user interface. The new frontend lives in
   `src/interactive.rs` to avoid the collision; renaming the old module is
   out of scope.

Why: it delivers the whole user-visible goal with no behavior risk to
existing users, the smallest CI/release footprint, and a clean path to
Option B (auto-launch) or C (split crate) later.

## 5. Public interface impact, compatibility, migration

- CLI: one new additive flag (`--interactive`/`-i`). All existing flags,
  config keys, output formats, and exit codes unchanged. `--help` gains one
  entry; the "No IPs could be resolved" warning gains a "try --interactive"
  hint (text only).
- Library: additive only. The form needs two things the API lacks today:
  (a) a way to build the `Opts` the form produces — already possible, the
  form constructs `Opts` directly; (b) live scan progress — `Scanner::run`
  returns everything at the end. A progress callback (e.g.
  `Scanner::with_progress(fn(usize, usize))` or an `mpsc` event stream) is
  proposed as a small additive API; exact shape is open question Q3.
  No existing API changes signature.
- Config file: no new keys. (A future `interactive = true` key is out of
  scope.)
- MSRV/toolchain: ratatui + crossterm must build on stable across the CI
  matrix (linux x86_64/arm64, macOS, Windows) and under the musl cross
  builds; the feature gate contains any fallout.
- Migration: none required. Users who never pass `--interactive` see no
  change except one `--help` line and one hint sentence.

## 6. Series shape (staged implementation, after discussion)

One row per pull request, in dependency order, eachgreen on its own:

| # | PR | Files | Depends on | Tested by | Lands alone? |
| - | -- | ----- | ---------- | --------- | ------------ |
| 1 | Progress-reporting scanner API (additive) | `src/scanner/mod.rs`, tests | — | unit tests with empty/excluded port sets (no sockets, per contributing.md) | yes |
| 2 | `interactive` Cargo feature + stub module | `Cargo.toml`, `Cargo.lock`, `src/interactive.rs`, `src/main.rs` (flag only, prints "not yet implemented" — or keep flag out until PR 4) | — | `cargo check --no-default-features`, `verify_cli` | yes |
| 3 | Form state → `Opts` + command preview (no terminal UI yet) | `src/interactive.rs`, tests | #1 for the run path (preview alone needs nothing) | unit tests: form fixtures → `Opts` equality, preview string snapshots | yes |
| 4 | ratatui event loop + wiring `--interactive` | `src/interactive.rs`, `src/main.rs` | #2, #3 | headless `TestBackend` tests for key handling; manual TTY runs (not in CI) | needs #2–#3 |
| 5 | Live scan view + run/export actions | `src/interactive.rs` | #1, #4 | `TestBackend` tests with a stubbed progress feed; opt-in Scan benchmark comparison for the scan path | needs #1, #4 |
| 6 | Docs: README entry, `docs/interactive-mode.md`, `--help` hint polish | `README.md`, `docs/`, `src/main.rs` (text) | #4 | read-back; `cargo doc` | yes (after #4) |

Notes: no patch mixes refactor with behavior change; PRs 1–3 are
independently useful (progress API, feature plumbing, preview logic) even if
the UI stalls.

## 7. Test strategy, documentation, risks

Test strategy:

- Unit tests for form→`Opts` conversion and command-preview rendering
  (pure, fast, no I/O).
- ratatui `TestBackend` tests for the event loop: keypress → state
  transitions, focus order, validation errors. No real terminal in CI.
- Scanner progress API tested with port sets that open no sockets
  (existing pattern: `scan_without_sockets_completes_on_a_current_thread_runtime`).
- Contributing.md rules apply unchanged: no network traffic, no spawned
  scans, no hostname resolution in automated tests. Manual TTY runs and the
  opt-in Scan benchmark cover real scanning behavior.
- `just test` (test + clippy ×2 + fmt + doc) must pass with and without
  `--features tui` (or `--no-default-features`, per Q1).

Documentation: README link + `docs/interactive-mode.md` (keybindings,
feature-flag builds, accessibility notes); `--help` entry; rustdoc on new
public items so `cargo doc` stays clean.

Risks and mitigations:

- Dependency weight / supply chain (ratatui, crossterm, transitive):
  contained by the feature gate; `--locked` builds; dependabot already
  covers the repo.
- Windows console and musl quirks: crossterm supports both, but the CI
  matrix cannot exercise a real TUI; manual release testing on Windows and
  a static musl binary is required before the final PR.
- Screen-reader accessibility: full-screen TUIs are poor with screen
  readers; `--accessible` bypasses the TUI entirely (falls back to current
  CLI behavior with a one-line notice), documented in Q4.
- Scope creep (dashboards, history, profiles): held off by the non-goals;
  follow-ups need their own issues.

## 8. Open questions for maintainers

- Q1: Should the `tui` Cargo feature be default-on (one install path,
  heavier default build) or opt-in (`--features tui`, lean default)?
- Q2: Flag spelling: `--interactive` only, or also `-i`? (Note: `-i` is
  currently unused; confirm no planned use.)
- Q3: Progress API shape: simple `FnMut(scanned, total)` callback on
  `Scanner`, or an async event stream (`mpsc`/`Stream` of scan events)?
  Callback is smaller; stream is more flexible for the live view.
- Q4: Is "accessible mode bypasses the TUI with a notice" the right call,
  or should there be a line-oriented interactive prompt for screen readers?
- Q5: May a later follow-up explore TTY-gated auto-launch (Option B), or
  should bare-`rustscan` keep exiting 1 forever?
- Q6: ratatui + crossterm acceptable as new dependencies, or is there a
  preferred TUI stack (e.g. iocraft, cursive)?
