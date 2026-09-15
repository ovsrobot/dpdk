# Wycheproof Validation

`dpdk-wycheproof_validation` validates DPDK cryptodev PMDs against Google
Wycheproof JSON vectors. It reads vector files directly at runtime; no copied
or generated vector corpus is kept in DPDK.

The initial implementation supports `AES-GCM`, `AES-CCM`,
`CHACHA20-POLY1305`, and `SM4-GCM` using `aead_test_schema_v1.json`, plus
HMAC-SHA1/224/256/384/512, HMAC-SHA3-224/256/384/512, HMAC-SM3, and AES-CMAC
using `mac_test_schema_v1.json`. For each compatible AEAD vector it maps:

| Wycheproof | DPDK AEAD operation |
|---|---|
| `key` | AEAD key |
| `iv` | AEAD IV |
| `aad` | AEAD associated data |
| `msg` | encryption input / expected decryption output |
| `ct` | expected encryption output / decryption input |
| `tag` | expected encryption tag / decryption digest |

`valid` vectors must encrypt and decrypt successfully with exact matching
ciphertext, tag, and plaintext. `invalid` vectors run decrypt only and must
complete with `RTE_CRYPTO_OP_STATUS_AUTH_FAILED`. The application reports
`acceptable` vectors as skipped until an algorithm-specific policy is added.
Vectors outside a PMD's advertised AEAD capability ranges are skipped and
counted separately.

For HMAC and AES-CMAC, `key`, `msg`, and `tag` map to the DPDK authentication
key, input data, and digest buffer. Valid vectors require exact generated tags;
invalid vectors require `RTE_CRYPTO_OP_STATUS_AUTH_FAILED` during verification.

AES-GMAC uses `mac_with_iv_test_schema_v1.json`; its `iv` maps to the DPDK
authentication IV in addition to the MAC fields above.

AES-CCM uses the DPDK AEAD API's CCM-specific layout: the nonce is stored one
byte after the IV pointer and the AAD is placed after its required 18-byte
prefix.

DSA verification is supported for the `dsa_p1363_verify_schema_v1.json` schema.
The group `p`, `q`, `g`, and `y` map to `rte_crypto_dsa_xform` and the verify
operation's public key; the per-test `msg` is hashed with the group `sha` via
the cryptodev auth path, and the fixed-width P1363 `sig` is split into `r` and
`s`. `valid` vectors must verify (`RTE_CRYPTO_OP_STATUS_SUCCESS`); `invalid`
vectors must not. This path needs a PMD advertising the asymmetric DSA verify
capability (for example `crypto_openssl`).

ECDH shared-secret computation is supported for the
`ecdh_ecpoint_test_schema_v1.json` schema. The group `curve` selects the DPDK
EC group; the per-test uncompressed `public` point (`0x04 || x || y`) maps to
`rte_crypto_ec_point`, `private` is the scalar, and the derived shared secret's
x-coordinate is compared against `shared`. `valid` vectors must produce the
expected secret; `invalid` vectors must not. Invalid-curve vectors (empty
`shared`) are skipped because on-curve validation is a separate ECDH
`PUB_KEY_VERIFY` op, not part of the raw shared-secret compute. This path needs
a PMD implementing ECDH (for example `crypto_qat`); the OpenSSL PMD does not
implement ECDH, so it capability-skips these vectors. Curves the PMD does not
support are capability-skipped rather than failed.

ECDSA verification is supported for the `ecdsa_p1363_verify_schema_v1.json`
schema. The group `publicKey.curve` selects the EC group and `publicKey.wx`,
`publicKey.wy` map to the public point `q` in `rte_crypto_ec_xform`; the
per-test `msg` is hashed with the group `sha` (using the leftmost `Ln` bits as
`e`), and the fixed-width P1363 `sig` is split into `r` and `s`. `valid`
signatures must verify; `invalid` ones must not. Non-canonical signature sizes
(not `2 * ceil(bitlen(n)/8)`) are skipped, since the fixed-width representation
cannot faithfully encode them. This path needs a PMD implementing ECDSA (for
example `crypto_qat`, curves secp256r1/384r1/521r1); the OpenSSL PMD does not
implement ECDSA, so it capability-skips these vectors.

Digest computation for DSA and ECDSA uses the symmetric auth path. When the
target device is asymmetric-only (for example the QAT asym device), the app
automatically selects a separate symmetric-capable device (for example the QAT
sym device) for hashing.

The dispatcher also recognizes AES-CBC-PKCS5, AES-EAX, AES-FF1, AES-GCM-SIV,
AES-KWP, AES-SIV-CMAC, AES-WRAP, AES-XTS, SM4-CCM, HMAC-SHA512/224,
HMAC-SHA512/256, RSA, ECDSA (DER, WebCrypto, and Bitcoin schemas), DSA (DER
`dsa_verify_schema_v1.json`), ECDH (DER, PEM, and WebCrypto schemas), and SEED
cipher files. Their operation-specific adapters are not implemented yet, so
they are reported as recognized-but-unsupported rather than silently folded
into unrelated files. HMAC requires separate generation and verification
operations; AES-XTS needs defined 64-bit data-unit-sequence to DPDK tweak
conversion; the remaining AES modes need cipher, padding, key-wrap, SIV, or
FPE adapters. DPDK exposes no SEED symmetric transform. RSA, the DER DSA
schema, the DER/WebCrypto/Bitcoin ECDSA schemas, and the non-ecpoint ECDH
schemas need per-schema padding, hash, key, and signature/point-encoding
adapters.

## Build

Jansson is required for JSON parsing. Build this example from the DPDK source
tree:

```sh
meson setup build -Dexamples=wycheproof_validation -Denable_drivers=crypto/openssl
meson compile -C build
```

## Run

Use the OpenSSL PMD for the first run. A file path processes that JSON file; a
directory processes supported JSON files directly within that directory.
Pass `--debug` to list every failed or skipped vector. Each record includes the
algorithm, `tcId` and result where available, and its reason.

```sh
./build/examples/dpdk-wycheproof_validation --vdev crypto_openssl -- \
  --vectors ../wycheproof/testvectors_v1/aes_gcm_test.json \
  --cryptodev crypto_openssl --debug
```

ECDH needs a PMD that implements it (the OpenSSL PMD does not). Build with the
QAT PMD (`-Denable_drivers=crypto/openssl,crypto/qat`) and run against a bound
QAT asymmetric device:

```sh
./build/examples/dpdk-wycheproof_validation -a 0000:14:00.1 -- \
  --vectors ../wycheproof/testvectors_v1/ecdh_secp256r1_ecpoint_test.json \
  --cryptodev 0000:14:00.1_qat_asym
```

The program exits nonzero when a parsed, supported vector fails validation. It
exits zero when all executed vectors pass, even when unsupported files or PMD
parameter combinations are skipped; the summary exposes those counts.
