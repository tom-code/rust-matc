# simple rust matter controller library

![build](https://github.com/tom-code/rust-matc/actions/workflows/rust.yml/badge.svg)

This is prototype of matter controller library in rust.

It supports controller side of:

* PASE - passcode authenticated session establishment
  * variant of spake 2+ https://datatracker.ietf.org/doc/rfc9383/
* CASE - certificate authenticated session establishment
  * variant of SIGMA https://www.iacr.org/cryptodb/archive/2003/CRYPTO/1495/1495.pdf
* Commisioning procedure
  * sign and push certificates to device
* Basic interactions
  * Read attribute
  * Invoke command


Use of demo application:
* demo application uses clap. use --help to learn all supported parameters
* create CA certificates in directory pem:\
  `cargo run --example demo ca-bootstrap`
* create key/certificate for controller with id 100:\
  `cargo run --example demo ca-create-controller 100`
* discover all commissionable devices using mdns:\
  `cargo run --example demo discover commissionable --timeout 3`
* discover all commissioned devices using mdns:\
  `cargo run --example demo discover commissioned --timeout 3`
* commission device (device ip address is 192.168.5.70, commissioning passcode is 123456, device id will be 300, device admin has id 100):\
  `cargo run --example demo commission 192.168.5.70:5540 100 300 123456`
* update fabric label in device:\
  `cargo run --example demo command invoke-command-update-fabric-label --device-address 192.168.5.70:5540 --controller-id 100 --device-id 300 "testfabric"`
* example how to use read command to read any attribute. This example lists all provisioned fabrics
  by reading attribute 1(fabrics) from cluster 62 (operational credentials) from endpoint 0:\
  `cargo run --example demo command read --device-address 192.168.5.70:5540  --controller-id 100 --device-id 300 0 62 1`
* if you want to start from scratch remove directory pem

