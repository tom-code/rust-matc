# simple rust matter protocol library

![build](https://github.com/tom-code/rust-matc/actions/workflows/rust.yml/badge.svg)
[![doc](https://github.com/tom-code/rust-matc/actions/workflows/doc.yml/badge.svg)](https://tom-code.github.io/rust-matc/matc/)

This is prototype of matter protocol library in rust (controller side).

[API doc](https://tom-code.github.io/rust-matc/matc/)

[Examples](https://github.com/tom-code/rust-matc/tree/main/examples)

It supports controller side of:

* PASE - passcode authenticated session establishment
  * variant of [spake 2+](https://datatracker.ietf.org/doc/rfc9383/)
* CASE - certificate authenticated session establishment
  * variant of [SIGMA](https://scispace.com/pdf/sigma-the-sign-and-mac-approach-to-authenticated-diffie-103fql3b25.pdf)
* Commisioning procedure
  * sign and push certificates to device
* Basic interactions
  * Read attribute
  * Invoke command

This library expects that device is already reachable using IPV4 or IPV6.
Bluetooth/BLE related communication is not yet supported.
To control device which first requires commissioning using BLE,
you must first commission using different controller (such as phone),
then using that controller enable commissioning.
For example in iphone/ios this is available under "enable pairing mode"
in device settings in Home app.
It will show "manual pairing code" which can be decoded
to obtain commissioning pass code (see decode-manual-pairing-code bellow).

Use of demo application:
* Compile demo application using cargo. Binary will be found usually in target/debug/examples/demo.\
  `cargo build --example demo`
* demo application uses clap. use --help to learn all supported parameters
* create CA certificates in directory pem:\
  `./demo ca-bootstrap`
* create key/certificate for controller with id 100:\
  `./demo ca-create-controller 100`
* discover all commissionable devices using mdns:\
  `./demo discover commissionable --timeout 3`
* discover all commissioned devices using mdns:\
  `./demo discover commissioned --timeout 3`
* discover specific device commissioned by us. query will filter based on device-id and "our" fabric:\
  `./demo discover commissioned2 --timeout 3 --device-id 300`
* if you have manual pairing code you can extract passcode from it using following command:\
  `demo decode-manual-pairing-code 1577-384-0075`
* commission device (device ip address is 192.168.5.70, commissioning passcode is 123456, device id will be 300, device admin has id 100):\
  `./demo commission 192.168.5.70:5540 100 300 123456`
* update fabric label in device:\
  `./demo command invoke-command-update-fabric-label --device-address 192.168.5.70:5540 --controller-id 100 --device-id 300 "testfabric"`
* example how to use read command to read any attribute. This example lists all provisioned fabrics
  by reading attribute 1(fabrics) from cluster 62 (operational credentials) from endpoint 0:\
  `./demo command read --device-address 192.168.5.70:5540  --controller-id 100 --device-id 300 0 62 1`
* example which will list all attributes in all clusters for all endpoints supported by device
  `./demo command list-attributes --device-address 192.168.5.70:5540  --controller-id 100 --device-id 300`
* turn device on/off:\
  `demo command invoke-command-on --device-address 192.168.5.70:5540 --controller-id 100 --device-id 300`

  `demo command invoke-command-off --device-address 192.168.5.70:5540 --controller-id 100 --device-id 300`
* if you want to start from scratch remove directory pem

Other demo application flags:
* --verbose - enable verbose logs
* --local-address - specify local bind address for matter protocol. Format is ip:port. This is
  ip/port which is used as source address for matter UDP requests.
  Default is 0.0.0.0:5555. When IPV6 is used this must be changed for example to --local-address "[\:\:]:5555"
* --cert-path - change directory where pem files with keys and certificates are stored