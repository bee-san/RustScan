"""Provision TCP memory for repeated scans on a disposable macOS CI runner."""

import ctypes
import json
import os
import subprocess


class Statistics(ctypes.Structure):
    # XNU's bsd/sys/mem_acct_private.h, struct memacct_statistics.
    _fields_ = [("peak", ctypes.c_uint64), ("allocated", ctypes.c_int64),
                ("softlimit", ctypes.c_uint64), ("hardlimit", ctypes.c_uint64),
                ("name", ctypes.c_char * 16)]


def tcp_memory(new_limit: int | None = None) -> dict:
    """Read the TCP accounting object, optionally raising its hard limit."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.sysctlnametomib.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int),
                                   ctypes.POINTER(ctypes.c_size_t)]
    libc.sysctl.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint,
                           ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                           ctypes.c_void_p, ctypes.c_size_t]
    mib = (ctypes.c_int * 24)()
    count = ctypes.c_size_t(22)
    if libc.sysctlnametomib(b"kern.memacct", mib, ctypes.byref(count)):
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))

    def query(operation: int, index: int, output, replacement=None):
        mib[count.value], mib[count.value + 1] = operation, index
        length = ctypes.c_size_t(ctypes.sizeof(output))
        if libc.sysctl(mib, count.value + 2, ctypes.byref(output), ctypes.byref(length),
                       ctypes.byref(replacement) if replacement is not None else None,
                       ctypes.sizeof(replacement) if replacement is not None else 0):
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        return length.value

    names = ctypes.create_string_buffer(8 * 16)
    length = query(5, 0, names)  # MEM_ACCT_SUBSYSTEMS
    index = next(i for i in range(length // 16)
                 if names.raw[i * 16:(i + 1) * 16].rstrip(b"\0") == b"TCP")
    stats = Statistics()
    query(6, index, stats)  # MEM_ACCT_ALL_SUBSYSTEM_STATISTICS
    previous_limit = stats.hardlimit
    if new_limit is not None and 0 < previous_limit < new_limit:
        query(3, index, ctypes.c_uint64(), ctypes.c_uint64(new_limit))
        query(6, index, stats)
    return {"previous_hardlimit": previous_limit,
            **{name: getattr(stats, name) for name in ("peak", "allocated", "softlimit", "hardlimit")}}


if __name__ == "__main__":
    # The default TCP budget is 1/32 of physical memory. Repeated 10,000-socket
    # batches hit ENOBUFS on Darwin 25.6 even on master. Give both builds 1/8
    # before timing; retain every listener check and performance threshold.
    memory = int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True))
    print(json.dumps(tcp_memory(memory // 8)))
