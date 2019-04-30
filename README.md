# vd-verifier

Application that serves as the other half of [vd](https://github.com/mmatous/vd) browser extension.

It receives console-arguments-like json message, parses it and compares checksum of input file with its digest.

## Build

You will need rust installed either via rustup or your distribution package manager.

```
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

Obviously, do not set the environment variable if you need the binary to
work on a different CPU.

## Install

Currently only Mozilla Firefox is supported.

### Linux

Download latest release and run `sudo install.sh`.

If you built vd yourself, copy result to install directory, then run `install.sh`

### Windows

Build, then run `install.ps1` with PowerShell.

If you built vd yourself, copy result to install directory, then run `install.ps1`

## About

### License

[GPLv3](LICENSE).

### Donate

BTC: [3B7EUmUb71q7WWdjLkyfssXVwzkTPSpuef](https://blockexplorer.com/address/3B7EUmUb71q7WWdjLkyfssXVwzkTPSpuef)

ETH: [0x7bd7BAF097F7AAA0733B92376aFf25B5E00FEa05](https://blockscout.com/eth/mainnet/address/0x7bd7baf097f7aaa0733b92376aff25b5e00fea05/)

XMR: 84TsTeWZ8ScZWPEK6yEuxCBG35UscCCd7h1bgjfwLYUcS9bgVPqXW4HUtBEYdRMbagauuuKGUwkxmRpsud2v12PmLQuyTd2
