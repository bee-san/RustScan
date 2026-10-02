#!/usr/bin/env python3
"""Untimed TCP diagnostics on a disposable CI runner, after the benchmark."""

import argparse
import json
import os
import subprocess

import scan_bench


def tcp_states():
    result = subprocess.run(
        ["netstat", "-an", "-p", "tcp"], capture_output=True, text=True, check=True
    )
    states = {}
    for line in result.stdout.splitlines():
        if line.startswith("tcp"):
            state = line.split()[-1]
            states[state] = states.get(state, 0) + 1
    return states


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="append", required=True)
    parser.add_argument("--json", required=True)
    args = parser.parse_args()
    builds = scan_bench.parse_pairs(args.build, "build")
    scenarios = [
        sc for sc in scan_bench.build_scenarios("Darwin", None, None, 5)
        if sc.name in {"tcp-sweep", "tcp-sweep-excluded", "tcp-sweep-b500", "tcp-sweep-b10000"}
    ]
    server, listeners = scan_bench.start_server([scan_bench.LOOPBACK])
    records = []
    try:
        for index in range(9):
            for scenario in scenarios:
                missing = False
                for name, binary in builds.items():
                    before = tcp_states()
                    result = subprocess.run(
                        [binary, *scenario.args(), "--scripts", "none", "--accessible",
                         "--no-banner", "--no-config"],
                        env=dict(os.environ, RUST_LOG="rustscan=info,rustscan::scanner=debug"),
                        capture_output=True, text=True, check=True,
                    )
                    opened = {
                        match.group(1) for line in result.stdout.splitlines()
                        if (match := scan_bench.OPEN_LINE.match(line))
                    }
                    absent = sorted(scenario.expected(listeners) - opened)
                    record = {
                        "round": index + 1, "build": name, "scenario": scenario.name,
                        "before": before, "after": tcp_states(), "missing": absent,
                        "errors": [line for line in result.stderr.splitlines()
                                   if "Typical socket connection errors" in line],
                    }
                    records.append(record)
                    print(json.dumps(record), flush=True)
                    missing |= bool(absent)
                if missing:
                    return
    finally:
        server.kill()
        server.wait()
        with open(args.json, "w", encoding="utf-8") as output:
            json.dump(records, output, indent=2)


if __name__ == "__main__":
    main()
