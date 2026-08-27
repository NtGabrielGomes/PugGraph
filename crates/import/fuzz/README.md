# Scanner parser fuzzing

Each importer's `parse` function is **pure and total** — any byte sequence either
parses or returns `Err`, never panics or allocates unbounded. The unit tests
(`*_parsing_is_total_on_hostile_input` in `../src/tests.rs`) assert this on a
fixed corpus; these libFuzzer targets assert it on an unbounded one.

This crate is **detached** from the core workspace (it declares its own empty
`[workspace]`), so `cargo test --workspace` never builds it. It is built only by
`cargo-fuzz`, which needs the nightly toolchain:

```sh
cargo install cargo-fuzz          # one-time
rustup toolchain install nightly  # one-time

cd core/crates/import
cargo +nightly fuzz run nmap       -- -runs=100000
cargo +nightly fuzz run bloodhound -- -runs=100000
cargo +nightly fuzz run netexec    -- -runs=100000
cargo +nightly fuzz run nessus     -- -runs=100000
```

A clean exit (no crash artifact under `fuzz/artifacts/`) is the pass condition.
