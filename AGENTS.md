# AGENTS.md

## Formatting

After any code change, run nightly rustfmt and ensure it's clean:

    cargo +nightly fmt
    cargo +nightly fmt -- --check

Also run typecheck/lint:

    cargo clippy --lib --tests

And the test suite:

    cargo nextest run
