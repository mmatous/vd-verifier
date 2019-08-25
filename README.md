# vd-verifier

Application that serves as the other half of [vd](https://github.com/mmatous/vd) browser extension.

It receives JSON message on standard input, parses it and compares input file with its digest/detached signature.

## Build
```
cargo build --release
```

## Test
```
cargo test -- --test-threads=1
```

## Install

Currently only Mozilla Firefox is supported.

### Linux

Download latest release and run `sudo install.sh`.

If you built `vd-verifier` yourself, copy result to install directory, then run `install.sh`

### Windows

Build or download, then right-click `install.ps1` and choose `Run with PowerShell`.

If you built `vd-verifier` yourself, copy result to install directory, then run `install.ps1`

## About

### License

[GPLv3](LICENSE).
