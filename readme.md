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
  * Invoke