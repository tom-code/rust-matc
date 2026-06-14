# simple rust matter protocol library

![build](https://github.com/tom-code/rust-matc/actions/workflows/rust.yml/badge.svg)
[![doc](https://github.com/tom-code/rust-matc/actions/workflows/doc.yml/badge.svg)](https://tom-code.github.io/rust-matc/matc/)

This is matter protocol library in rust (controller side).

[API doc](https://tom-code.github.io/rust-matc/matc/)

[Examples](https://github.com/tom-code/rust-matc/tree/main/examples)

[Matter controller desktop application also demonstrates use of this library](https://github.com/tom-code/matc-ui)

It supports controller side of:

* PASE - passcode authenticated session establishment
  * variant of [spake 2+](https://datatracker.ietf.org/doc/rfc9383/)
* CASE - certificate authenticated session establishment
  * variant of [SIGMA](https://scispace.com/pdf/sigma-the-sign-and-mac-approach-to-authenticated-diffie-103fql3b25.pdf)
* Commissioning procedure
  * sign and push certificates to device
  * BLE commissioning with Wi-Fi/Thread credential provisioning (opt-in, `--features ble`)
* Basic interactions
  * Read/Write attributes
  * Invoke commands
  * Subscribe for notifications

See [examples](https://github.com/tom-code/rust-matc/tree/main/examples) for usage, including the high-level `devman_demo`, BLE commissioning, and the low-level `demo` CLI.
