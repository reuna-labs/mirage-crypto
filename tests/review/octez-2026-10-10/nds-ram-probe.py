#!/usr/bin/env python3
"""Compare the unchanged NDS suite using bounded, non-swappable temporary RAM."""
import os
import pathlib
import subprocess
import time

temporary = "/work/diagnostics/nds-ramtmp"
mount = next(
    line.split()
    for line in pathlib.Path("/proc/self/mountinfo").read_text().splitlines()
    if line.split()[4] == temporary
)
separator = mount.index("-")
assert mount[separator + 1] == "tmpfs"
assert "noswap" in mount[separator + 3].split(",")
env = os.environ.copy()
env["TMPDIR"] = temporary
env["CI"] = "true"
command = [
    "/work/src/_build/default/src/lib_riscv_nds/test/main.exe",
    "/flaky",
    "/ci_disabled",
]
with pathlib.Path("/work/logs/nds-ram-probe.log").open("x", buffering=1) as log:
    log.write("Unchanged NDS executable and Dune alias arguments; temporary RAM only.\n")
    log.write("Mount: " + " ".join(mount) + "\n")
    log.write("Command: " + repr(command) + "\n")
    start = time.monotonic()
    result = subprocess.run(
        command, cwd="/work/diagnostics", env=env, stdout=log, stderr=subprocess.STDOUT
    )
    log.write("\nElapsed seconds: %.3f\n" % (time.monotonic() - start))
    log.write("GATE EXIT: %d\n" % result.returncode)
raise SystemExit(result.returncode)
