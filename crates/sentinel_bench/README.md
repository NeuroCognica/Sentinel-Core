# Sentinel Bench

Run the benchmark harness to measure event append throughput, chain verification, identity reducer cost, and signing/verification latency.


Usage:

```bash
cd crates/sentinel_bench
cargo run --release
```

You can also use the repository-level run scripts which capture output to `crates/sentinel_bench/bench-results`:

Linux/macOS:

```bash
./scripts/run_bench.sh
```

Windows PowerShell:

```powershell
.\scripts\run_bench.ps1
```

Results are printed to stdout and written to `crates/sentinel_bench/bench-results` and sample event logs are written to `target/bench_data`.

Notes:
- Adjust sizes in `src/main.rs` to include 1_000_000 events if you have sufficient disk and time.
- For accurate numbers, run with `--release` and on an otherwise idle machine.
