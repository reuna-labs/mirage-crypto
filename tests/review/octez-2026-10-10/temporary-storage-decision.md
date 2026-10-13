# Temporary storage decision, 2026-10-13

The second ext4 full-unit attempt remained live after more than eight hours,
with 63/139 NDS tests completed. Its NDS process had used approximately four
minutes of CPU and repeatedly waited in `jbd2_log_wait_commit`; I/O counters
continued advancing. This was not treated as a hang or a test failure.

A concurrent diagnostic used the identical compiled NDS executable and the
identical Dune alias arguments (`/flaky /ci_disabled`), with unchanged sample
counts. Only `TMPDIR` differed: a 1 GiB tmpfs mount with `noswap`. All 139 tests
passed in 109.748 seconds. See `nds-ram-probe.py` and `nds-ram-probe.log`.
The original external ext4 run remained intact during this comparison.

This evidence justifies deliberately stopping that slow attempt and running
the complete `make test-unit` gate again with bounded, non-swappable temporary
RAM. The diagnostic is not a substitute for the full repository gate. Source,
build outputs, toolchains, caches and retained logs remain on the external
drive. The container root remains read-only. No test filters, sample counts,
test source or cryptographic source are changed for this adjustment.

The RAM filesystem preserves Linux hardlink semantics needed by RocksDB.
It does not establish power-loss durability. The original failing snapshot
seed and the exact filesystem reproducer had already passed on the external
ext4 image; those results are retained separately.

The replacement full gate uses a 4 GiB `noswap` temporary filesystem and a
1.5 GiB available-memory stop threshold. The existing external-drive and
internal-metadata free-space reserves remain in force. The interrupted run
and its partial output remain evidence of an incomplete attempt, not a pass.
