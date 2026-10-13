#!/usr/bin/env python3
"""Full unit gate: external build, bounded non-swappable temporary RAM."""
import os
import pathlib
import shutil
import signal
import stat
import subprocess
import sys
import time

base = pathlib.Path("/work")
logs = base / "logs"
log_name = sys.argv[1] if len(sys.argv) == 2 else "final-unit-ram.log"
if pathlib.Path(log_name).name != log_name or not log_name.endswith(".log"):
    raise SystemExit("Expected a log basename ending in .log")
log_prefix = log_name[:-4]
required = {
    "HOME": "/work/home",
    "OPAMROOT": "/work/opam",
    "CARGO_HOME": "/work/cargo",
    "RUSTUP_HOME": "/work/rustup",
    "XDG_CACHE_HOME": "/work/cache",
    "TMPDIR": "/work/tmp",
}
for key, expected in required.items():
    if os.environ.get(key) != expected:
        raise SystemExit("Unexpected environment: " + key)

# The last mount at an over-mounted path is the visible one.
mounts = {
    fields[4]: fields
    for line in pathlib.Path("/proc/self/mountinfo").read_text().splitlines()
    if (fields := line.split())
}
assert "ro" in mounts["/"][5].split(",")
assert "/work" in mounts
assert mounts["/work"][mounts["/work"].index("-") + 1] != "tmpfs"
assert (base / "src/_build").resolve().is_relative_to(base)
for target in ["/work/tmp", "/tmp", "/var/tmp"]:
    mount = mounts[target]
    separator = mount.index("-")
    assert mount[separator + 1] == "tmpfs"
    options = mount[separator + 3].split(",")
    assert "noswap" in options and "size=4194304k" in options


def resource_error():
    if shutil.disk_usage(base).free < 20 * 1024**3:
        return "External drive has less than 20 GiB free"
    if shutil.disk_usage("/").free < 2 * 1024**3:
        return "Internal metadata storage has less than 2 GiB free"
    memory = dict(
        (line.split()[0].rstrip(":"), int(line.split()[1]))
        for line in pathlib.Path("/proc/meminfo").read_text().splitlines()
    )
    if memory["MemAvailable"] < 1536 * 1024:
        return "Available VM memory is below the 1.5 GiB reserve"
    return None


def checkpoint_nds():
    for process in pathlib.Path("/proc").iterdir():
        if not process.name.isdecimal():
            continue
        try:
            if os.readlink(process / "cwd") != "/work/src/_build/default/src/lib_riscv_nds/test":
                continue
            for fd, stream in [("1", "stdout"), ("2", "stderr")]:
                source = process / "fd" / fd
                if stat.S_ISREG(source.stat().st_mode):
                    target = logs / (log_prefix + ".nds." + stream + ".partial.log")
                    temporary = target.with_suffix(".tmp")
                    temporary.write_bytes(source.read_bytes())
                    temporary.replace(target)
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue


reason = resource_error()
if reason:
    raise SystemExit(reason)
env = os.environ.copy()
env.update(
    PATH="/work/bin:/work/cargo/bin:" + env["PATH"],
    DUNE_ARGS="-j 1",
    DUNE_CACHE_ROOT="/work/cache/dune",
    CI="true",
)
command = ["opam", "exec", "--switch=octez-5.3", "--", "make", "test-unit"]
with (logs / log_name).open("x", buffering=1) as log:
    log.write("External source/build/cache/logs; temporary RAM capped at 4 GiB, noswap.\n")
    log.write("Reserves: external 20 GiB; internal metadata 2 GiB; available RAM 1.5 GiB.\n")
    log.write("Command: " + repr(command) + "\n")
    log.write("LD_LIBRARY_PATH: " + env.get("LD_LIBRARY_PATH", "") + "\n")
    for target in ["/", "/work", "/work/tmp", "/tmp", "/var/tmp"]:
        log.write("Mount: " + " ".join(mounts[target]) + "\n")
    process = subprocess.Popen(
        command, cwd=base / "src", env=env, stdout=log,
        stderr=subprocess.STDOUT, start_new_session=True,
    )
    while process.poll() is None:
        checkpoint_nds()
        reason = resource_error()
        if reason:
            log.write("\nVALIDATION STOPPED: " + reason + "\n")
            os.killpg(process.pid, signal.SIGINT)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=15)
            raise SystemExit(75)
        time.sleep(5)
    log.write("\nGATE EXIT: " + str(process.returncode) + "\n")
raise SystemExit(process.returncode)
