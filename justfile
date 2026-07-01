default:
    @just --list

build:
    cargo build

run *args:
    cargo run -- {{args}}

test:
    cargo test

fmt:
    cargo fmt

fmt-check:
    cargo fmt --check

clippy:
    cargo clippy --all-targets -- -D warnings

check:
    cargo check

build-nodefault:
    cargo build --no-default-features

check-macos:
    cargo check --target x86_64-apple-darwin

check-freebsd:
    cargo check --target x86_64-unknown-freebsd

snapshot-update:
    INSTA_UPDATE=always cargo test

man:
    cargo run -- --man

completions shell:
    cargo run -- --completions {{shell}}

ci: fmt-check clippy test
