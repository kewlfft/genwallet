# genwallet

Ethereum wallet generator with pattern matching.

## Build

```bash
cargo build --release
```

## Usage

```bash
./target/release/genwallet --start abc --end def --count 1
```

## Security

- Generated wallets are encrypted with passwords
- Private keys are redacted by default
- Use `--full-key` to show complete private keys 