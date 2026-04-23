# Device Certificate Chain (PKI)

Matter requires a 3-level PKI chain: **PAA - PAI - DAC**.

- **PAA** (Product Attestation Authority) - root CA, `pathlen:1`
- **PAI** (Product Attestation Intermediate) - intermediate CA, `pathlen:0`
- **DAC** (Device Attestation Certificate) - leaf cert, signed by PAI

## Generate Certificates

From the project root:

```bash
# 1. Create PAA (root CA)
cargo run --example pki -- create-ca \
  --vendor-id 65521 \
  --out-cert device-cert/paa-cert.pem \
  --out-key device-cert/paa-key.pem

# 2. Create PAI (intermediate CA, signed by PAA)
cargo run --example pki -- create-pai \
  --vendor-id 65521 \
  --ca-cert device-cert/paa-cert.pem \
  --ca-key device-cert/paa-key.pem \
  --out-cert device-cert/pai-cert.pem \
  --out-key device-cert/pai-key.pem

# 3. Create DAC (device cert, signed by PAI)
cargo run --example pki -- create-dac \
  --vendor-id 65521 \
  --product-id 32768 \
  --ca-cert device-cert/pai-cert.pem \
  --ca-key device-cert/pai-key.pem \
  --out-cert device-cert/dac-cert.pem \
  --out-key device-cert/dac-key.pem
```

## Verify Chain

```bash
openssl verify -CAfile device-cert/paa-cert.pem \
  -untrusted device-cert/pai-cert.pem \
  device-cert/dac-cert.pem
```
