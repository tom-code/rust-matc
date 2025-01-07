# simple rust controller library

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
* create CA certificates in directory pem: `cargo run --example demo3 ca-bootstrap`
* create key/certificate for controller with id 100: `cargo run --example demo3 ca-create-controller 100`
* commission device (device ip address is 192.168.5.70, commissioning passcode is 123456, device is will be 300, device admin has id 100): `cargo run --example demo3 commission 192.168.5.70:5540 100 300 123456`
* if you want to start from scratch remove directory pem