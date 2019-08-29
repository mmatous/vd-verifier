# vd-verifier

[![Build Status](https://travis-ci.com/mmatous/vd-verifier.svg?branch=master)](https://travis-ci.com/mmatous/vd-verifier)

Application that serves as the other half of [vd](https://github.com/mmatous/vd) browser extension.

It receives JSON message on standard input, parses it and compares input file with its digest/detached signature.

## Build

### Linux

```bash
cargo build --release
```

### Cross-compile for Windows

Docker and [cross](https://github.com/rust-embedded/cross) are used for Windows build..  
```bash
docker build -t vd/x86_64-pc-windows-gnu ./docker
cross --target x86_64-pc-windows-gnu --no-default-features

```

## Test
```bash
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
