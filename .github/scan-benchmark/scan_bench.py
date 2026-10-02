#!/usr/bin/env python3
"""Compare RustScan builds by scanning listeners on the loopback interface.

CI-only tooling for ``.github/workflows/scan-benchmark.yml``; it is not part
of the test suite. It port-scans 127.0.0.1, so only run it on a disposable CI
runner, never on a developer machine or a shared host.

``run`` starts ``serve`` (TCP listeners and UDP responders on 127.0.0.1) in a
separate process, runs every scenario with every build (interleaving the
builds so that drift on the runner affects them all alike), checks that all
builds report the same open ports, and writes the raw measurements as JSON
plus a Markdown summary of the medians. On Linux the workflow also sets up a
host behind an artificial delay (a network namespace on the runner, with its
own ``serve``), so that answers arrive after a round trip, as they do from a
remote host, instead of while the probe is being sent.

Measured per run:

* scan time: RustScan's own "Portscan" timer (``RUST_LOG=rustscan=info``),
  reported as throughput (sockets per second);
* wall time of the whole process, and the time until the first ``Open`` line
  appears on stdout (latency to the first result);
* peak RSS and CPU time (user + system) of the process;
* peak number of open file descriptors (Windows: handles) and of threads,
  sampled every few milliseconds while the scan runs.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import selectors
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field

LOOPBACK = "127.0.0.1"

# Ports `serve` listens on. They stay below 32768, i.e. below the ephemeral
# port ranges of Linux (32768-60999), macOS and Windows (49152-65535): a scan
# of a port inside the ephemeral range can occasionally connect a socket to
# itself and report a bogus open port.
TCP_PORTS = tuple(range(1024, 32768, 101))  # 315 open TCP ports
UDP_PORTS = tuple(range(1031, 32768, 997))  # 32 open UDP ports
SWEEP = (1, 32767)

SAMPLE_INTERVAL = 0.005  # seconds between fd/thread samples
RUN_TIMEOUT = 300  # seconds before a run is killed and counted as failed


# --------------------------------------------------------------------------
# Listener process
# --------------------------------------------------------------------------


def serve(addresses: list[str]) -> int:
    """Accepts (and closes) TCP connections and answers every UDP datagram."""
    selector = selectors.DefaultSelector()
    bound: dict[str, dict[str, list[int]]] = {"tcp": {}, "udp": {}, "busy": {}}

    for address in addresses:
        for kind, ports in (("tcp", TCP_PORTS), ("udp", UDP_PORTS)):
            sock_type = socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM
            for port in ports:
                sock = socket.socket(socket.AF_INET, sock_type)
                if os.name != "nt":
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.bind((address, port))
                except OSError:
                    sock.close()
                    bound["busy"].setdefault(f"{kind} {address}", []).append(port)
                    continue
                if kind == "tcp":
                    sock.listen(1024)
                sock.setblocking(False)
                selector.register(sock, selectors.EVENT_READ, kind)
                bound[kind].setdefault(address, []).append(port)

    print(json.dumps(bound), flush=True)

    while True:
        for key, _ in selector.select(timeout=1.0):
            sock = key.fileobj
            if key.data == "tcp":
                while True:
                    try:
                        conn, _ = sock.accept()
                    except OSError:  # BlockingIOError once the queue is empty
                        break
                    conn.close()
            else:
                while True:
                    try:
                        _, peer = sock.recvfrom(4096)
                    except ConnectionResetError:
                        # Windows reports an earlier ICMP error here; skip it.
                        continue
                    except OSError:  # BlockingIOError once the queue is empty
                        break
                    try:
                        sock.sendto(b"rustscan-benchmark\n", peer)
                    except OSError:
                        pass


def start_server(addresses: list[str]) -> tuple[subprocess.Popen, dict]:
    args = [arg for address in addresses for arg in ("--address", address)]
    proc = subprocess.Popen(
        [sys.executable, os.path.abspath(__file__), "serve", *args],
        stdout=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
    )
    line = proc.stdout.readline()
    if not line:
        raise SystemExit("the listener process exited before it was ready")
    return proc, json.loads(line)


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Scenario:
    name: str
    title: str
    addresses: tuple[str, ...]
    ranges: tuple[tuple[int, int], ...] = ()
    ports: tuple[int, ...] = ()
    batch: int = 4500
    timeout_ms: int = 1500
    udp: bool = False
    repeat: int = 1  # extra samples for very short scenarios
    excluded_ports: tuple[int, ...] = ()

    @property
    def sockets(self) -> int:
        span = sum(end - start + 1 for start, end in self.ranges)
        excluded = sum(self.covers(port) for port in set(self.excluded_ports))
        return len(self.addresses) * (len(self.ports) + span - excluded)

    def covers(self, port: int) -> bool:
        return port in self.ports or any(s <= port <= e for s, e in self.ranges)

    def args(self) -> list[str]:
        args = ["-a", ",".join(self.addresses)]
        if self.ports:
            args += ["-p", ",".join(map(str, self.ports))]
        else:
            args += ["-r", ",".join(f"{s}-{e}" for s, e in self.ranges)]
        args += ["-b", str(self.batch), "-t", str(self.timeout_ms)]
        if self.udp:
            args.append("--udp")
        if self.excluded_ports:
            args += ["--exclude-ports", ",".join(map(str, self.excluded_ports))]
        return args

    def expected(self, listeners: dict) -> set[str]:
        by_address = listeners["udp" if self.udp else "tcp"]
        return {
            f"{address}:{port}"
            for address in self.addresses
            for port in by_address.get(address, [])
            if self.covers(port) and port not in self.excluded_ports
        }

    def describe(self) -> str:
        hosts = f"{len(self.addresses)} addresses" if len(self.addresses) > 1 else self.addresses[0]
        return f"{self.title}: `{' '.join(self.args()[2:])}` on {hosts}"


def build_scenarios(
    system: str, filtered: tuple[int, int] | None, delayed: str | None, delay_ms: int
) -> list[Scenario]:
    lo = (LOOPBACK,)
    if system == "Windows":
        # Windows retries a refused connection for about a second, so every
        # closed port there takes as long as a filtered one: sweep fewer.
        sweep, small_sweep = ((1, 8191),), ((1, 2047),)
    else:
        sweep = small_sweep = (SWEEP,)

    def ports(ranges: tuple[tuple[int, int], ...]) -> str:
        return f"{sum(e - s + 1 for s, e in ranges):,} ports"

    scenarios = [
        Scenario("tcp-1-port", "TCP, 1 open port", lo, ports=(TCP_PORTS[0],), repeat=3),
        Scenario("tcp-sweep", f"TCP, {ports(sweep)}, default batch", lo, sweep),
        Scenario(
            "tcp-sweep-excluded",
            f"TCP, {ports(sweep)}, 1,024 excluded ports",
            lo,
            sweep,
            excluded_ports=tuple(range(1024, 2048)),
        ),
        Scenario(
            "tcp-sweep-b500", f"TCP, {ports(small_sweep)}, small batch", lo, small_sweep, batch=500
        ),
        Scenario("tcp-sweep-b10000", f"TCP, {ports(sweep)}, large batch", lo, sweep, batch=10000),
    ]
    if system == "Linux":
        # Linux answers on all of 127.0.0.0/8; other systems only on 127.0.0.1.
        hosts = tuple(f"127.0.0.{i}" for i in range(1, 9))
        scenarios.append(
            Scenario("tcp-8-hosts", "TCP, 8 hosts x 4,096 ports", hosts, ((1, 4096),))
        )
    if delayed:
        scenarios.append(
            Scenario("tcp-delayed", f"TCP, {ports(sweep)}, {delay_ms} ms away", (delayed,), sweep)
        )
    if filtered:
        dropped = (filtered,)
        scenarios += [
            Scenario(
                "tcp-filtered", "TCP, 2,000 filtered ports", lo, dropped, batch=500, timeout_ms=250
            ),
            Scenario(
                "tcp-mixed",
                f"TCP, {ports(sweep)} + 2,000 filtered ports",
                lo,
                sweep + dropped,
                timeout_ms=500,
            ),
        ]
    scenarios.append(
        Scenario("udp-sweep", f"UDP, {ports(sweep)}", lo, sweep, timeout_ms=500, udp=True)
    )
    if delayed:
        scenarios.append(
            Scenario(
                "udp-delayed",
                f"UDP, {ports(sweep)}, {delay_ms} ms away",
                (delayed,),
                sweep,
                timeout_ms=500,
                udp=True,
            )
        )
    if filtered:
        scenarios.append(
            Scenario(
                "udp-filtered",
                "UDP, 2,000 filtered ports",
                lo,
                (filtered,),
                batch=500,
                timeout_ms=250,
                udp=True,
            )
        )
    return scenarios


# --------------------------------------------------------------------------
# Running one scan
# --------------------------------------------------------------------------


@dataclass
class RunResult:
    build: str
    scenario: str
    sockets: int = 0
    ok: bool = True
    error: str = ""
    returncode: int | None = None
    wall_s: float | None = None
    scan_s: float | None = None
    first_open_s: float | None = None
    rss_kb: int | None = None
    cpu_s: float | None = None
    peak_fds: int | None = None
    peak_threads: int | None = None
    open: list[str] = field(default_factory=list)

    @property
    def rate(self) -> float | None:
        return self.sockets / self.scan_s if self.scan_s else None


SCAN_TIME = re.compile(r"Portscan\s*\|\s*([0-9.]+)\s*s")
OPEN_LINE = re.compile(r"^Open (\S+)$")
SUMMARY_LINE = re.compile(r"^(\S+) -> \[([0-9,]*)\]$")


class Sampler(threading.Thread):
    """Samples the open descriptors and the threads of a running process."""

    def __init__(self, proc: subprocess.Popen):
        super().__init__(daemon=True)
        self.proc = proc
        self.done = threading.Event()
        self.peak_fds: int | None = None
        self.peak_threads: int | None = None
        self.system = platform.system()
        self.libproc = darwin_libproc() if self.system == "Darwin" else None

    def sample(self) -> tuple[int | None, int | None]:
        pid = self.proc.pid
        if self.system == "Linux":
            fds = len(os.listdir(f"/proc/{pid}/fd"))
            threads = None
            with open(f"/proc/{pid}/status", encoding="ascii", errors="replace") as status:
                for line in status:
                    if line.startswith("Threads:"):
                        threads = int(line.split()[1])
                        break
            return fds, threads
        if self.libproc is not None:
            return darwin_fds_and_threads(self.libproc, pid)
        if self.system == "Windows":
            return windows_handle_count(self.proc), None
        return None, None

    def run(self) -> None:
        while not self.done.is_set():
            try:
                fds, threads = self.sample()
            except (OSError, ValueError):
                return  # the process is gone
            if fds is not None:
                self.peak_fds = max(self.peak_fds or 0, fds)
            if threads is not None:
                self.peak_threads = max(self.peak_threads or 0, threads)
            self.done.wait(SAMPLE_INTERVAL)


def darwin_libproc():
    import ctypes

    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
    except OSError:
        return None
    libproc.proc_pidinfo.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    libproc.proc_pidinfo.restype = ctypes.c_int
    return libproc


def darwin_fds_and_threads(libproc, pid: int) -> tuple[int | None, int | None]:
    import ctypes

    proc_pidlistfds, proc_pidtaskinfo = 1, 4
    size = libproc.proc_pidinfo(pid, proc_pidlistfds, 0, None, 0)
    if size <= 0:
        raise OSError("process is gone")
    buf = ctypes.create_string_buffer(size)
    used = libproc.proc_pidinfo(pid, proc_pidlistfds, 0, ctypes.addressof(buf), size)
    if used <= 0:
        raise OSError("process is gone")
    fds = used // 8  # sizeof(struct proc_fdinfo)

    class TaskInfo(ctypes.Structure):  # struct proc_taskinfo
        _fields_ = [
            *((name, ctypes.c_uint64) for name in ("vsize", "rsize", "user", "system", "tu", "ts")),
            *(
                (name, ctypes.c_int32)
                for name in (
                    "policy",
                    "faults",
                    "pageins",
                    "cow_faults",
                    "messages_sent",
                    "messages_received",
                    "syscalls_mach",
                    "syscalls_unix",
                    "csw",
                    "threadnum",
                    "numrunning",
                    "priority",
                )
            ),
        ]

    info = TaskInfo()
    got = libproc.proc_pidinfo(
        pid, proc_pidtaskinfo, 0, ctypes.addressof(info), ctypes.sizeof(info)
    )
    return fds, (info.threadnum if got == ctypes.sizeof(info) else None)


def windows_handle_count(proc: subprocess.Popen) -> int | None:
    import ctypes
    from ctypes import wintypes

    count = wintypes.DWORD()
    handle = wintypes.HANDLE(int(proc._handle))  # Popen keeps the handle open
    if not ctypes.windll.kernel32.GetProcessHandleCount(handle, ctypes.byref(count)):
        raise OSError("process is gone")
    return count.value


def windows_memory_and_cpu(proc: subprocess.Popen) -> tuple[int | None, float | None]:
    import ctypes
    from ctypes import wintypes

    class Counters(ctypes.Structure):  # PROCESS_MEMORY_COUNTERS
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    handle = wintypes.HANDLE(int(proc._handle))
    counters = Counters()
    counters.cb = ctypes.sizeof(counters)
    rss_kb = None
    if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
        rss_kb = counters.PeakWorkingSetSize // 1024

    times = [wintypes.FILETIME() for _ in range(4)]  # creation, exit, kernel, user
    cpu_s = None
    if ctypes.windll.kernel32.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
        ticks = sum((t.dwHighDateTime << 32) | t.dwLowDateTime for t in times[2:])
        cpu_s = ticks / 1e7  # 100 ns units
    return rss_kb, cpu_s


def run_once(name: str, binary: str, scenario: Scenario) -> RunResult:
    result = RunResult(build=name, scenario=scenario.name, sockets=scenario.sockets)
    cmd = [
        binary,
        *scenario.args(),
        "--scripts",
        "none",
        "--accessible",
        "--no-banner",
        "--no-config",
    ]
    env = dict(os.environ, RUST_LOG="rustscan=info")
    stdout_lines: list[str] = []
    stderr_chunks: list[bytes] = []

    start = time.perf_counter()
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, env=env
    )

    def read_stdout() -> None:
        for raw in proc.stdout:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if result.first_open_s is None and line.startswith("Open "):
                result.first_open_s = time.perf_counter() - start
            stdout_lines.append(line)

    readers = [
        threading.Thread(target=read_stdout, daemon=True),
        threading.Thread(target=lambda: stderr_chunks.append(proc.stderr.read()), daemon=True),
    ]
    for reader in readers:
        reader.start()
    sampler = Sampler(proc)
    sampler.start()
    # On Unix the child is reaped with os.wait4 below, so the watchdog must
    # not go through Popen (which would try to reap it as well).
    kill = proc.kill if os.name == "nt" else lambda: os.kill(proc.pid, signal.SIGKILL)
    watchdog = threading.Timer(RUN_TIMEOUT, kill)
    watchdog.start()

    try:
        if hasattr(os, "wait4"):
            _, status, usage = os.wait4(proc.pid, 0)
            result.wall_s = time.perf_counter() - start
            proc.returncode = os.waitstatus_to_exitcode(status)
            maxrss = usage.ru_maxrss  # KiB on Linux, bytes on macOS
            result.rss_kb = maxrss // 1024 if platform.system() == "Darwin" else maxrss
            result.cpu_s = usage.ru_utime + usage.ru_stime
        else:
            proc.wait()
            result.wall_s = time.perf_counter() - start
            result.rss_kb, result.cpu_s = windows_memory_and_cpu(proc)
    finally:
        watchdog.cancel()
        sampler.done.set()
        sampler.join()
        for reader in readers:
            reader.join()

    result.returncode = proc.returncode
    result.peak_fds = sampler.peak_fds
    result.peak_threads = sampler.peak_threads
    stderr = b"".join(stderr_chunks).decode("utf-8", "replace")

    opened: set[str] = set()
    summarised: set[str] = set()
    for line in stdout_lines:
        if match := OPEN_LINE.match(line):
            opened.add(match.group(1))
        elif match := SUMMARY_LINE.match(line):
            summarised.update(f"{match.group(1)}:{p}" for p in match.group(2).split(",") if p)
    result.open = sorted(opened)

    if scan_time := SCAN_TIME.search(stderr):
        result.scan_s = float(scan_time.group(1))

    problems = []
    if proc.returncode != 0:
        problems.append(f"exit code {proc.returncode}")
    if result.scan_s is None:
        problems.append("no 'Portscan' timer in the log")
    if summarised != opened:
        problems.append(f"'Open' lines and the summary disagree: {sorted(summarised ^ opened)[:5]}")
    if problems:
        result.ok = False
        tail = "\n".join(stderr.strip().splitlines()[-15:])
        result.error = "; ".join(problems) + (f"\nstderr tail:\n{tail}" if tail else "")
    return result


# --------------------------------------------------------------------------
# Environment
# --------------------------------------------------------------------------


def sysctl(*names: str) -> list[str]:
    return subprocess.run(
        ["sysctl", "-n", *names], capture_output=True, text=True, check=True
    ).stdout.split("\n")


def ephemeral_range() -> tuple[int, int] | None:
    system = platform.system()
    try:
        if system == "Linux":
            with open("/proc/sys/net/ipv4/ip_local_port_range", encoding="ascii") as f:
                low, high = map(int, f.read().split())
            return low, high
        if system == "Darwin":
            first, last = sysctl("net.inet.ip.portrange.first", "net.inet.ip.portrange.last")[:2]
            return int(first), int(last)
    except (OSError, ValueError, subprocess.CalledProcessError):
        return None
    return (49152, 65535) if system == "Windows" else None


def environment() -> dict[str, object]:
    system = platform.system()
    info: dict[str, object] = {
        "system": system,
        "release": platform.release(),
        "machine": platform.machine(),
        "cpus": os.cpu_count(),
        "cpu": platform.processor(),
        "python": platform.python_version(),
        "ephemeral_ports": ephemeral_range(),
    }
    try:
        if system == "Linux":
            with open("/proc/cpuinfo", encoding="ascii", errors="replace") as f:
                for line in f:
                    if line.lower().startswith(("model name", "cpu model")):
                        info["cpu"] = line.split(":", 1)[1].strip()
                        break
        elif system == "Darwin":
            info["cpu"] = sysctl("machdep.cpu.brand_string")[0].strip()
    except (OSError, subprocess.CalledProcessError):
        pass
    try:
        import resource

        info["open_file_limit"] = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    except (ImportError, OSError, ValueError):
        pass
    return info


# --------------------------------------------------------------------------
# Analysis and reporting
# --------------------------------------------------------------------------

Results = dict[str, dict[str, list[RunResult]]]

# key, title, formatter, higher is better
METRICS = (
    ("rate", "Throughput (sockets/s, from RustScan's scan timer)", lambda v: f"{v:,.0f}", True),
    ("wall_s", "Wall time of the whole process", lambda v: f"{v * 1000:,.0f} ms", False),
    ("first_open_s", "Time to the first open port", lambda v: f"{v * 1000:,.1f} ms", False),
    ("rss_kb", "Peak RSS", lambda v: f"{v / 1024:,.1f} MiB", False),
    ("cpu_s", "CPU time (user + system)", lambda v: f"{v * 1000:,.0f} ms", False),
    ("peak_fds", "Peak open descriptors (sampled; Windows: handles)", lambda v: f"{v:,.0f}", False),
    ("peak_threads", "Peak threads (sampled)", lambda v: f"{v:,.0f}", False),
)
FLAG_WORSE = 10.0  # percent


def metric_values(runs: list[RunResult], key: str) -> list[float]:
    return [float(getattr(r, key)) for r in runs if r.ok and getattr(r, key) is not None]


def median(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def worse_by(value: float, base: float, higher_is_better: bool) -> float:
    """How much worse `value` is than `base`, in percent (negative: better)."""
    pct = (value / base - 1.0) * 100.0
    return -pct if higher_is_better else pct


def check_open_ports(
    results: Results, scenarios: list[Scenario], listeners: dict, baseline: str
) -> tuple[list[str], list[str], list[str]]:
    """Returns (failed runs, open-port mismatches, notes).

    No build may miss more listeners than the baseline: none at all if the
    baseline found every listener in every run, or barely more if it did not
    either (a runner too slow for the scenario's timeout). Ports that are
    open beyond the listeners (services already running on the runner) must
    match what the baseline found: a build may not miss a port the baseline
    found in every run, nor report one the baseline never found.
    """
    failures, mismatches, notes = [], [], []
    for sc in scenarios:
        expected = sc.expected(listeners)
        per_build = results[sc.name]

        def missed(runs: list[RunResult]) -> int:
            return sum(len(expected - set(r.open)) for r in runs if r.ok)

        base_missed = missed(per_build[baseline])
        allowed = base_missed + max(3, base_missed // 4) if base_missed else 0
        if base_missed:
            notes.append(
                f"`{sc.name}`: `{baseline}` itself missed {base_missed} of "
                f"{len(expected) * len(per_build[baseline])} listener answers"
            )

        base_extra = [set(r.open) - expected for r in per_build[baseline] if r.ok]
        always = set.intersection(*base_extra) if base_extra else set()
        ever = set.union(*base_extra) if base_extra else set()
        for name, runs in per_build.items():
            for index, res in enumerate(runs, start=1):
                if not res.ok:
                    failures.append(f"`{sc.name}` `{name}` run {index}: {res.error.splitlines()[0]}")
            if name == baseline:
                continue
            if (count := missed(runs)) > allowed:
                mismatches.append(
                    f"`{sc.name}` `{name}`: missed {count} listener answers "
                    f"(`{baseline}`: {base_missed})"
                )
            for index, res in enumerate(runs, start=1):
                if not res.ok:
                    continue
                found = set(res.open)
                where = f"`{sc.name}` `{name}` run {index}"
                if lost := always - found:
                    mismatches.append(f"{where}: missed ports `{baseline}` always found {sorted(lost)[:5]}")
                if bogus := (found - expected) - ever:
                    mismatches.append(f"{where}: reported ports `{baseline}` never found {sorted(bogus)[:5]}")
    return failures, mismatches, notes


def gate(
    results: Results,
    scenarios: list[Scenario],
    baseline: str,
    candidate: str,
    max_slowdown: float,
    max_memory: float,
) -> list[str]:
    """Scenarios where `candidate` is clearly worse than `baseline`."""
    problems = []
    for sc in scenarios:
        checks = [("wall_s", False, max_slowdown, 0.002), ("rss_kb", False, max_memory, 1024)]
        if sc.sockets >= 1000:  # throughput is meaningless for a handful of sockets
            checks.append(("rate", True, max_slowdown, 0))
        for key, higher, limit, floor in checks:
            base = median(metric_values(results[sc.name][baseline], key))
            value = median(metric_values(results[sc.name][candidate], key))
            if not base or value is None or abs(value - base) <= floor:
                continue
            if (worse := worse_by(value, base, higher)) > limit:
                problems.append(f"{sc.name}: {key} {worse:+.1f}% worse than {baseline} (limit {limit}%)")
    return problems


def render_markdown(report: dict, results: Results, scenarios: list[Scenario]) -> str:
    builds = report["builds"]
    baseline = report["baseline"]
    env = report["environment"]
    out = [f"### Scan benchmark: {env['system']} {env['machine']}", ""]
    out.append(
        "; ".join(f"`{b['name']}`: {b['label']}" for b in builds)
        + f". {report['runs']} interleaved runs per build and scenario (`tcp-1-port`: x3), medians."
        f" Runner: {env.get('cpu') or '?'}, {env['cpus']} CPUs, {env['system']} {env['release']},"
        f" open-file limit {env.get('open_file_limit', 'n/a')}."
    )
    out.append("")

    problems = report["failures"] + report["mismatches"]
    tcp = sum(len(ports) for ports in report["listeners"]["tcp"].values())
    udp = sum(len(ports) for ports in report["listeners"]["udp"].values())
    if not problems:
        out.append(
            f"✅ Every run of every build exited cleanly; no build missed more of the {tcp} TCP "
            f"and {udp} UDP listeners than `{baseline}`, or disagreed with it about other ports."
        )
    else:
        out.append(f"❌ {len(report['failures'])} failed runs, {len(report['mismatches'])} open-port mismatches:")
        out += [f"- {p}" for p in problems[:25]]
    if report["notes"]:
        out.append("")
        out += [f"- ⚠️ {note}" for note in report["notes"]]
    out.append("")
    out.append("| Scenario | What is scanned |")
    out.append("|---|---|")
    out += [f"| `{sc.name}` | {sc.describe()} ({sc.sockets:,} sockets) |" for sc in scenarios]
    out.append("")
    out.append(f"Changes are relative to `{baseline}`; ❗ marks a median more than {FLAG_WORSE:.0f}% worse.")
    out.append("")

    for key, title, fmt, higher in METRICS:
        rows = []
        for sc in scenarios:
            base_value = median(metric_values(results[sc.name][baseline], key))
            cells = []
            for build in builds:
                value = median(metric_values(results[sc.name][build["name"]], key))
                if value is None:
                    cells.append("–")
                    continue
                cell = fmt(value)
                if build["name"] != baseline and base_value:
                    pct = (value / base_value - 1.0) * 100.0
                    flag = " ❗" if worse_by(value, base_value, higher) > FLAG_WORSE else ""
                    cell += f" ({pct:+.1f}%{flag})"
                cells.append(cell)
            if any(c != "–" for c in cells):
                rows.append(f"| `{sc.name}` | " + " | ".join(cells) + " |")
        out.append(f"**{title}**")
        out.append("")
        if rows:
            out.append("| Scenario | " + " | ".join(f"`{b['name']}`" for b in builds) + " |")
            out.append("|---|" + "---:|" * len(builds))
            out += rows
        else:
            out.append("_Not measured on this platform._")
        out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def parse_pairs(values: list[str], option: str) -> dict[str, str]:
    pairs = {}
    for value in values:
        name, sep, rest = value.partition("=")
        if not sep or not name or not rest:
            raise SystemExit(f"--{option} expects NAME=VALUE, got {value!r}")
        pairs[name] = rest
    return pairs


def run(args: argparse.Namespace) -> int:
    builds = parse_pairs(args.build, "build")
    labels = parse_pairs(args.label, "label")
    baseline = args.baseline or next(iter(builds))
    if baseline not in builds:
        raise SystemExit(f"unknown baseline build {baseline!r}")
    for name, path in builds.items():
        if not os.path.isfile(path):
            raise SystemExit(f"build {name!r}: {path} does not exist")
    if args.gate and args.gate not in builds:
        raise SystemExit(f"unknown --gate build {args.gate!r}")
    if args.delayed_host and not args.delayed_listeners:
        raise SystemExit("--delayed-host needs --delayed-listeners")

    filtered = None
    if args.filtered:
        low, _, high = args.filtered.partition("-")
        filtered = (int(low), int(high))

    scenarios = build_scenarios(platform.system(), filtered, args.delayed_host, args.delay_ms)
    if args.only:
        wanted = set(args.only.split(","))
        scenarios = [sc for sc in scenarios if sc.name in wanted]

    if ephemeral := ephemeral_range():
        low, high = ephemeral
        for sc in scenarios:
            for start, end in sc.ranges:
                if start <= high and end >= low:
                    raise SystemExit(
                        f"scenario {sc.name} scans {start}-{end}, which overlaps the ephemeral "
                        f"port range {low}-{high}: a scan could connect a socket to itself"
                    )

    server, listeners = start_server([LOOPBACK])
    if args.delayed_host:
        # The workflow runs a second `serve` on the delayed host (inside a
        # network namespace) and stores its first line in this file.
        with open(args.delayed_listeners, encoding="utf-8") as f:
            far = json.loads(f.readline())
        for kind in ("tcp", "udp"):
            listeners[kind][args.delayed_host] = far[kind].get(args.delayed_host, [])
    for kind in ("tcp", "udp"):
        counts = {address: len(ports) for address, ports in listeners[kind].items()}
        print(f"{kind} listeners: {counts}", flush=True)
    if listeners["busy"]:
        print(f"already in use: {listeners['busy']}", flush=True)

    names = list(builds)
    results: Results = {sc.name: {name: [] for name in names} for sc in scenarios}
    try:
        warmup = next((sc for sc in scenarios if sc.name == "tcp-sweep"), scenarios[0])
        for name in names:
            run_once(name, builds[name], warmup)

        rounds = args.runs * max(sc.repeat for sc in scenarios)
        for index in range(rounds):
            shift = index % len(names)
            order = names[shift:] + names[:shift]
            for sc in scenarios:
                if index >= args.runs * sc.repeat:
                    continue
                for name in order:
                    res = run_once(name, builds[name], sc)
                    results[sc.name][name].append(res)
                    print(
                        f"[{index + 1}/{rounds}] {sc.name:<17} {name:<14} ok={res.ok} "
                        f"scan={res.scan_s} wall={res.wall_s} first={res.first_open_s} "
                        f"rss={res.rss_kb} cpu={res.cpu_s} fds={res.peak_fds} "
                        f"threads={res.peak_threads} open={len(res.open)}",
                        flush=True,
                    )
                    if not res.ok:
                        print(f"    {res.error}", flush=True)
    finally:
        server.kill()
        server.wait()

    failures, mismatches, notes = check_open_ports(results, scenarios, listeners, baseline)
    report = {
        "environment": environment(),
        "baseline": baseline,
        "builds": [{"name": n, "label": labels.get(n, n), "path": builds[n]} for n in names],
        "runs": args.runs,
        "listeners": listeners,
        "scenarios": [asdict(sc) | {"sockets": sc.sockets} for sc in scenarios],
        "results": {
            sc: {n: [asdict(r) | {"rate": r.rate} for r in runs] for n, runs in per.items()}
            for sc, per in results.items()
        },
        "failures": failures,
        "mismatches": mismatches,
        "notes": notes,
    }
    markdown = render_markdown(report, results, scenarios)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=1)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write(markdown + "\n")
    print(markdown)

    status = 1 if failures or mismatches else 0
    if args.gate:
        for problem in gate(results, scenarios, baseline, args.gate, args.max_slowdown, args.max_memory):
            print(f"::error::performance regression: {problem}", flush=True)
            status = 1
    return status


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    listen = sub.add_parser("serve", help="run the loopback listeners (started by `run`)")
    listen.add_argument("--address", action="append", default=[], help="address to listen on")
    bench = sub.add_parser("run", help="benchmark the given builds")
    bench.add_argument("--build", action="append", required=True, metavar="NAME=PATH")
    bench.add_argument("--label", action="append", default=[], metavar="NAME=TEXT")
    bench.add_argument("--baseline", help="build the others are compared with (default: the first)")
    bench.add_argument("--runs", type=int, default=9, help="interleaved runs per build and scenario")
    bench.add_argument(
        "--filtered", metavar="START-END", help="ports the runner drops; enables filtered scenarios"
    )
    bench.add_argument(
        "--delayed-host",
        metavar="ADDRESS",
        help="address behind an artificial delay, with its own `serve`; enables delayed scenarios",
    )
    bench.add_argument(
        "--delayed-listeners", metavar="FILE", help="first output line of that host's `serve`"
    )
    bench.add_argument("--delay-ms", type=int, default=5, help="that delay, for the summary")
    bench.add_argument("--only", metavar="NAMES", help="comma-separated scenarios to run")
    bench.add_argument("--json", help="write the raw results to this file")
    bench.add_argument("--markdown", help="write the Markdown summary to this file")
    bench.add_argument("--gate", metavar="NAME", help="fail if this build regresses against the baseline")
    bench.add_argument("--max-slowdown", type=float, default=15.0, help="percent, throughput and wall time")
    bench.add_argument("--max-memory", type=float, default=25.0, help="percent, peak RSS")
    args = parser.parse_args()
    # The summary contains emoji; Windows runners default to a legacy code page.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    return serve(args.address or [LOOPBACK]) if args.command == "serve" else run(args)


if __name__ == "__main__":
    sys.exit(main())
