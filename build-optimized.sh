#!/bin/bash

# Optimized build script for genwallet
export RUSTFLAGS="-C target-cpu=native -C target-feature=+crt-static -C lto=fat -C codegen-units=1 -C panic=abort -C strip=symbols"

echo "Building with optimizations..."
cargo build --release

echo "Build complete! Binary size:"
ls -lh target/release/genwallet

echo "Running performance test..."
time target/release/genwallet --wallets 5 --start a --end b 