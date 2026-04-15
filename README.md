# FROST2 Rust Implementation

Rust port of the FROST variants comparison (FROST1, Binding, FROST2+, FROST2#, ROAST) using Ristretto255 and SHA-512, with **decentralized key generation (DKG)**.

## Requirements

- [Rust](https://rustup.rs/) (1.70+)

## Build & Run

```bash
cd frost2_rust
cargo build --release
cargo run --release -- -n 10 -t 5 -r 10
```

## CLI Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--n` | `-n` | 10 | Total number of signers |
| `--t` | `-t` | 5 | Threshold |
| `--alpha` | | t | Number of signers participating |
| `--trials` | `-r` | 10 | Number of trials for mean/median/std |
| `--seed` | `-s` | (none) | Random seed for reproducibility |
| `--message` | | "test" | Message to sign |
| `--output` | `-o` | (none) | Export results to CSV file |

## Examples

```bash
# Default run (n=10, t=5, 10 trials)
cargo run --release

# Custom parameters with CSV export
cargo run --release -- -n 20 -t 7 -r 5 -o results.csv

# Reproducible run with seed
cargo run --release -- -s 42 -r 3
```

After generating `results.csv`, regenerate plain-text/LaTeX tables, plotting data, and optional figures:

```bash
python3 scripts/generate_benchmark_artifacts.py
```

Output is written to `benchmark_artifacts/` (install **matplotlib** to also emit PNG/PDF charts).

## Project Structure

```
frost2_rust/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs       # Module exports
    ├── main.rs      # CLI entry point
    ├── backend.rs   # Ristretto255 group adapter (curve25519-dalek)
    ├── core.rs      # FROST2/FROST2+/FROST2# logic
    └── roast.rs     # ROAST wrapper
```

## Dependencies

- **curve25519-dalek** – Ristretto255 curve operations
- **sha2** – SHA-512 hashing
- **rand** / **rand_chacha** – RNG (reproducible for benchmarking)
- **clap** – CLI argument parsing
- **csv** – CSV export

## Output

The program prints a comparison table in MJCA TABLE 3 format with mean, median, and standard deviation for each phase (setup, keygen, preprocess, signing, combining, verifying, preprocess per participant, signing per participant) across all five variants.
