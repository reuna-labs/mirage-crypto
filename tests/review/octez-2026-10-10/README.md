# Octez external-drive validation

## Final result

All required gates passed on 2026-10-13. Octez implementation commit:
`d6601b2f79039d46cf493da5fd9ba9eb8fcad4b9` (`reuna@native-crypto-signers`).
`gate-results.json` indexes the successful raw logs, and
`source-comparison-final.json` confirms all 350 implementation files match
the tested snapshot, with no frozen protocol changes. The only additional
source difference is the validation README.

The complete `make test-unit` result is `final-unit-ram-r2.log`, with all
three stages successful and `GATE EXIT: 0`. The 56-member
`external-validation-logs.tar.gz` archive also preserves environment logs
and the original source manifest; every member is checked against the
accompanying SHA-256 index. Historical checkpoints below document failed,
interrupted and successful attempts rather than replacing this final result.
The intended fork URL is still required for Octez publication.

The previous validation container was absent when work resumed on 2026-10-10.
The old evidence archive remains in `../octez-2026-10-04/evidence.tar.gz`.
No result is inferred for its interrupted final unit run.

## Storage

- Container: `octez-native-external`
- External host directory:
  `/Volumes/Seagate Expansion Drive/reuna/builds/octez-native-signers-20261010`
- Container workspace: `/work/src`; build output: `/work/src/_build`
- External toolchains/caches: `/work/opam`, `/work/rustup`, `/work/cargo`,
  `/work/cache`, `/work/formatter`
- Current temporary storage: a shared 4 GiB `noswap` tmpfs mounted at
  `/work/tmp` and `/tmp`, with its `var-tmp` subdirectory at `/var/tmp`.
  The previous ext4 image remains on the external drive for the retained
  filesystem comparison; see the temporary I/O correction below.
- Logs and preserved prior evidence: `/work/logs`
- Host source is mounted read-only at `/source`.

All 30,677 staged source files were checked against `source-manifest.json`.
The source baseline remains `34a13eb8750c3f8458b57a6573e0dba86434e0ae`, with
the current uncommitted feature-branch changes included.

The small Debian system-tooling layer is on the internal Docker filesystem;
source, compiler builds, dependency downloads and Octez build products are on
the external drive. Other Docker containers and volumes are not involved.

## Guarded commands

The runner `/work/bin/octez-external-run.py` verifies mount and environment
paths and requires a read-only container root. It stops a gate on external
free space below 20 GiB or internal free space below 2 GiB. The internal reserve
was reduced from 8 GiB on October 13 after confirming the read-only root,
external writable mounts, and unchanged 238,719-byte writable container layer
across the long run. The 2 GiB reserve is for Docker metadata; compilation and
test files remain external. An initial check
of shared internal-storage growth also counted unrelated Docker activity;
the read-only root now prevents build writes to that layer directly.
It sets the existing Octez CI test configuration (`CI=true`), defaults to four
Dune jobs, and sets the external Dune cache path. A caller-supplied `DUNE_ARGS`
overrides the job default. The full unit gate will use `DUNE_ARGS=-j 1` to avoid
the observed Snoop/Tezt interference through shared temporary directories.

Example:

```sh
docker exec octez-native-external python3 /work/bin/octez-external-run.py \
  repository-build.log opam exec --switch=octez-5.3 -- dune build -j 4
```

Use a distinct log filename for each gate/retry. Check `GATE EXIT: 0` and the
scope of that command before recording a pass. Compiler/dependency setup and
DAL fixture verification passed. The full repository `dune build -j 4`
passed (`GATE EXIT: 0`); its log is also preserved here as
`repository-build.log`. Final formatting, full lint and manifest consistency
also passed; their logs are preserved here. The first full unit run stopped
without passing, as detailed below. `final-sequence.py` and `final-sequence.log`
describe that terminal run. The current `final-sequence-ext4.py` waits for the
original-seed snapshot property recheck, checks for source changes and the
connection-pool recheck, then runs serial unit tests, both protocol-compilation
aliases and final signer timing. It stops at the first failing gate and records
each transition in `final-sequence-ext4.log`.

The task-owned system image is `reuna/octez-native-validation:20261010`
(`sha256:685c4c413e8f540fc6593c7966153984f745db136ee023d154688dd92543db41`).
The disposable setup container has been removed. The validation container
uses `ReadonlyRootfs=true`; its only persistent writable mounts are on the
external drive. `/run` is a small memory-backed filesystem.

## Source identity review

`source-comparison.json` compares all 351 changed tracked/untracked candidate
files against the external validation snapshot, excluding the two generated
root `.install` files. All changed implementation files match. The sole
mismatch is `scripts/crypto/README.md`, whose host copy records newer evidence
and corrected final Solo5 measurements. It must be synchronized with the final
report after the outstanding gates finish.

`whitespace-review.json` records the pre-commit `git diff --check` findings.
All findings are in pinned upstream BLST files; those bytes are preserved for
source identity. No finding is in the authored adapter or integration changes.

`source-comparison-20261013.json` repeats the comparison after the protocol and
timing gates: all 350 implementation files match the tested snapshot, and the
only differing candidate is the updated assurance README. Frozen protocol
sources are unchanged. The exact 351-file candidate set is staged on
`reuna@native-crypto-signers`, excluding the two generated root `.install`
files; no implementation commit has been made while the unit gate is pending.

## Unit run and environment correction (2026-10-12)

The first full serial unit run stopped with exit 75 when shared internal free
space fell below 8 GiB. Its complete log is `final-unit.log`; the sequence
termination is in `final-sequence.log`. This is not a unit-gate pass. Earlier
`.partial.log` files are checkpoints only.

Two test failures were also recorded. The connection-pool suite could not
resolve the `http` service because Debian's minimal image lacked
`/etc/services`. The container now binds Debian bookworm `netbase` 6.4's
services/protocols files read-only from external storage. All three connection
pool tests pass with the restored service database.

The NDS snapshot property failed while RocksDB hard-linked a checkpoint SST.
Its exact shrunk ten-operation sequence fails twice on the external shared
filesystem and passes twice on Linux tmpfs. The same executable also passes
on an ext4 image stored on the external drive. No crypto or NDS source was
changed to obtain these results.

The replacement `octez-native-external` container keeps the source/build cache
and read-only root. `native-tmp-entrypoint.sh` mounts the task-owned 8 GiB
`linux-test-tmp.ext4` image at `/work/tmp`, with bind mounts at `/tmp` and
`/var/tmp`. Loop-device access and `SYS_ADMIN` are used for those mounts;
the container is not privileged. The old stopped container is retained as
`octez-native-external-before-ext4` until the replacement is verified.

The original failing snapshot property passed with seed 481264812 on October
12 at 04:48 UTC, using its unchanged default sample count. Its complete log is
`nds-snapshot-property-ext4.log` (`GATE EXIT: 0`). The queue then started the
full serial unit gate. Full unit, protocol and final timing gates remain
incomplete.

At 10:33 UTC the full unit gate was still live in the NDS executable, with
63 of 139 tests reported successful. Dune buffers this executable's output
until it exits; `nds-full-suite-ext4.partial.log` preserves that checkpoint
directly from its stdout file. This is partial evidence, not a full-suite pass.

The ext4 unit run subsequently stopped at 2026-10-12 21:29:42 UTC with exit
75 because internal Docker free space fell below 8 GiB. Its terminal logs are
`final-unit-ext4.log` and `final-sequence-ext4.log`. The container later exited
at 2026-10-13 03:57 UTC; it was not OOM-killed. On October 13 it was restarted
only to inspect retained state. No validation gate restarted: internal Docker
free space was about 6.2 GiB, while the external drive still had 555 GiB free.

The interrupted executable's temporary stdout/stderr files no longer exist.
The retained 63/139 checkpoint is therefore the last preserved NDS result;
neither subsequent tests nor full-suite completion are inferred. Docker reports
only 238,719 writable bytes for each task container, with the shared task image
about 1.16 GB. Its system-wide inventory reports 12.83 GB of unused build cache.
Permission to remove that shared cache was requested separately because the
earlier cleanup authorization covered task-owned artifacts after validation.

`final-sequence-resume.py` has now started after a successful storage preflight.
It preserves the
remaining gates and unit sample counts, runs the two protocol aliases and
signer timing before the full unit retry, and checkpoints the NDS executable's
regular stdout/stderr files every five seconds into external partial logs.
It enforces the revised storage guard and refuses to overwrite gate logs.
`run-gate-before-reserve-fix.py` retains the previous runner for interpreting
the interrupted runs. `storage-preflight-20261013.log` records the mount,
environment and capacity preflight; it is not a cryptographic test result.
The shared-cache cleanup request is no longer needed to resume validation;
no shared cache was deleted.

The complete `@runtest_compile_protocol` alias passed on October 13 at 08:55
UTC (`GATE EXIT: 0`), with its log retained as `final-protocol-compile.log`.
The complete `@runtest_out_of_opam` alias also passed at 08:56 UTC; its log is
`final-protocol-out-of-opam.log`. Expected syntax/primitive rejection diagnostics
in that log are successful negative tests, and the command ended with exit 0.
Final HACL/secp timing completed at 08:57 UTC; `final-signer-timing.log` records
all eight populations at 50,000 samples per class and maximum absolute Welch t
1.9575. This run includes the final public-key heap-layout correction. It is
virtualized timing evidence, not constant-time proof; production entropy
acquisition is excluded. The full unit retry started immediately afterward
and remains outstanding.

The October 13 unit retry has a retained checkpoint of 63/139 NDS tests passed
(`final-unit-ext4-r2.nds.stdout.partial.log`, last success at 14:57 UTC).
The process remained live with increasing I/O when inspected at 16:35 UTC.
Its stderr checkpoint is empty. These are partial results, not a unit-gate pass.

## Temporary I/O correction

The ext4 retry was deliberately interrupted at 17:13 UTC after a comparison
proved a substantial storage bottleneck: the identical NDS executable and
alias arguments passed all 139 tests in 109.748 seconds with a bounded
non-swappable temporary RAM filesystem. See `nds-ram-probe.log`, its runner,
and `temporary-storage-decision.md`. The ext4 attempt's terminal logs are
`final-unit-ext4-r2.log` (gate -2) and `final-sequence-resume.log` (exit 254).

The full `make test-unit` retry uses `run-unit-ram.py`, with temporary storage
capped at 4 GiB and `noswap`, plus a 1.5 GiB available-memory reserve. All large
build output, caches and retained logs remain external. Its current log is
`/work/logs/final-unit-ram.log`. All 139 NDS tests passed within this full gate
at 17:17:40 UTC, followed by all 178 store tests. That attempt finished with
gate exit 2: two Snoop cram outputs cached since October 11 contained leftover
temporary-file warnings, and the benchmark Python initialization test lacked
the system Python shared library. Its complete log is retained locally.

The two generated cram outputs were archived before removal, so Dune can
regenerate them against clean temporary storage. Expected test output was
unchanged. Matching Debian `libpython3.11` and `libpython3.11-dev` packages
(3.11.2-6+deb12u9, arm64) were extracted under `/work/system-prereqs`, with
that library directory supplied through `LD_LIBRARY_PATH`. A loader check
passed; package hashes are in `python-runtime-prerequisite.json`.
The complete retry in `final-unit-ram-r2.log` passed all three unit stages.

## Cleanup

Keep this workspace until final gates, commit and evidence export finish.
The user authorized cleanup afterward. Remove only task-owned artifacts;
the other contents of the external drive and unrelated Docker resources
are outside this task.
