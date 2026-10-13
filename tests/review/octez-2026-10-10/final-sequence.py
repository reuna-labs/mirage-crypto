#!/usr/bin/env python3
"""Continue the external validation gates, sequentially, stopping on failure."""
import os
import pathlib
import subprocess
import sys
import time

logs = pathlib.Path("/work/logs")
fmt = logs / "final-format.log"
runner = ["python3", "/work/bin/octez-external-run.py"]
opam = ["opam", "exec", "--switch=octez-5.3", "--"]
with (logs / "final-sequence.log").open("x", buffering=1) as journal:
    def record(message):
        journal.write(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " " + message + "\n")
    record("Waiting for the already-running final-format.log gate")
    while True:
        content = fmt.read_text()
        if "GATE EXIT:" in content:
            if not content.rstrip().endswith("GATE EXIT: 0"):
                record("STOP: formatting failed")
                sys.exit(1)
            break
        processes = subprocess.check_output(["ps", "-eo", "args"], text=True)
        if not any(line.startswith("python3 /work/bin/octez-external-run.py final-format.log ") for line in processes.splitlines()):
            record("STOP: formatting guard is absent without a terminal result")
            sys.exit(1)
        time.sleep(5)
    record("Formatting passed")
    clean = subprocess.run(["git", "diff", "--exit-code"], cwd="/work/src", stdout=journal, stderr=subprocess.STDOUT)
    if clean.returncode:
        record("STOP: formatting changed tracked source; review required")
        sys.exit(clean.returncode)
    gates = [
        ("final-lint.log", ["make", "check-linting"], {}),
        ("final-manifest.log", ["make", "-C", "manifest", "check"], {}),
        ("final-unit.log", ["make", "test-unit"], {"DUNE_ARGS": "-j 1"}),
        ("final-protocol-compile.log", ["dune", "build", "-j", "4", "--profile=dev", "@runtest_compile_protocol"], {}),
        ("final-protocol-out-of-opam.log", ["dune", "build", "-j", "4", "--profile=dev", "@runtest_out_of_opam"], {}),
        ("final-signer-timing.log", ["sh", "scripts/crypto/check-signer-timing.sh", "50000"], {}),
    ]
    for name, command, overrides in gates:
        if (logs / name).exists():
            record("STOP: refusing to overwrite " + name)
            sys.exit(1)
        record("START " + name + " " + repr(command))
        env = os.environ.copy()
        env.update(overrides)
        result = subprocess.run(runner + [name] + opam + command, env=env)
        record("END " + name + " exit=" + str(result.returncode))
        if result.returncode:
            sys.exit(result.returncode)
    record("All queued gates passed; final source/evidence review and commit remain")
