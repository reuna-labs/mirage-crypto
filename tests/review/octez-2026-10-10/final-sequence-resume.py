#!/usr/bin/env python3
"""Resume outstanding gates and retain NDS output across interruptions."""
import os
import pathlib
import stat
import subprocess
import sys
import time

logs = pathlib.Path("/work/logs")
runner = ["python3", "/work/bin/octez-external-run.py"]
opam = ["opam", "exec", "--switch=octez-5.3", "--"]


def checkpoint_nds():
    """Copy regular output files only; never consume a pipe or socket."""
    for process in pathlib.Path("/proc").iterdir():
        if not process.name.isdecimal():
            continue
        try:
            if os.readlink(process / "cwd") != "/work/src/_build/default/src/lib_riscv_nds/test":
                continue
            for fd, stream in [("1", "stdout"), ("2", "stderr")]:
                source = process / "fd" / fd
                if not stat.S_ISREG(source.stat().st_mode):
                    continue
                data = source.read_bytes()
                target = logs / ("final-unit-ext4-r2.nds." + stream + ".partial.log")
                temporary = target.with_suffix(".tmp")
                temporary.write_bytes(data)
                temporary.replace(target)
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue


with (logs / "final-sequence-resume.log").open("x", buffering=1) as journal:
    def record(message):
        journal.write(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " " + message + "\n")

    for prerequisite in ["nds-snapshot-property-ext4.log", "connpool-netbase-recheck.log"]:
        if not (logs / prerequisite).read_text().rstrip().endswith("GATE EXIT: 0"):
            record("STOP: prerequisite has not passed: " + prerequisite)
            sys.exit(1)
    clean = subprocess.run(["git", "diff", "--exit-code"], cwd="/work/src", stdout=journal, stderr=subprocess.STDOUT)
    if clean.returncode:
        record("STOP: tracked source differs from the validation snapshot")
        sys.exit(clean.returncode)

    # Independent remaining gates first; full unit scope and samples are unchanged.
    gates = [
        ("final-protocol-compile.log", ["dune", "build", "-j", "4", "--profile=dev", "@runtest_compile_protocol"], {}),
        ("final-protocol-out-of-opam.log", ["dune", "build", "-j", "4", "--profile=dev", "@runtest_out_of_opam"], {}),
        ("final-signer-timing.log", ["sh", "scripts/crypto/check-signer-timing.sh", "50000"], {}),
        ("final-unit-ext4-r2.log", ["make", "test-unit"], {"DUNE_ARGS": "-j 1"}),
    ]
    for name, command, overrides in gates:
        if (logs / name).exists():
            record("STOP: refusing to overwrite " + name)
            sys.exit(1)
        record("START " + name + " " + repr(command))
        env = os.environ.copy()
        env.update(overrides)
        process = subprocess.Popen(runner + [name] + opam + command, env=env)
        while process.poll() is None:
            if name == "final-unit-ext4-r2.log":
                checkpoint_nds()
            time.sleep(5)
        record("END " + name + " exit=" + str(process.returncode))
        if process.returncode:
            sys.exit(process.returncode)
    record("All queued gates passed; final source/evidence review and commit remain")
