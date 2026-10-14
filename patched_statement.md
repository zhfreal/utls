# Patch Statement: utls (v1.9.0-patch1)

This document describes the functional and architectural changes introduced in branch `main-patched` of `zhfreal/utls` on top of upstream `metacubex/utls v1.9.0-mod-meta` and backported features from `refraction-networking/utls:master`.

---

## Module 1: Upstream Sync to MetaCubeX v1.9.0-mod-meta
- **Core Standard Library Modernization**: Rebased onto modern Go crypto/tls standard library codebase.
- **Post-Quantum Hybrid Key Exchange**: Native integration of NIST FIPS 203 ML-KEM (`crypto/mlkem`) supporting `X25519MLKEM768`, `SecP256r1MLKEM768`, and `SecP384r1MLKEM1024`.
- **RFC 8879 Certificate Compression**: Full support for Brotli, Zstandard, and Zlib certificate compression.
- **Enhanced Browser Profiles**: Includes Safari 26.3 (`aa6edf4`, parity with Xray-core), Firefox 148 with KeyShare reuse, and Chrome 133+.
- **MetaCubeX Reality & JLS**: Updated Reality Server and ShadowQUIC JLS authentication for v1.9.0 TLS 1.3 state structures.

---

## Module 2: Post-Quantum Authentication (ML-DSA-65) Reality Support
- **Configuration Fields**: Extended `RealityConfig` with:
  - `Mldsa65Verify ([]byte)`: Client-side public key verification object.
  - `Mldsa65Key ([]byte)`: Server-side private key bytes for certificate signing.
- **Dependency Integration**: Integrated NIST FIPS 204 post-quantum module `github.com/cloudflare/circl/sign/mldsa/mldsa65` (v1.6.4).
- **Server Certificate Allocation & Signing**:
  - Implemented `realityServerCertMldsa65`: Allocates a server certificate structure formatted to accommodate the ML-DSA-65 signature size (3309 bytes).
  - Implemented `realitySignMldsa65`: Cryptographically signs the TLS 1.3 server handshake context and injects the resulting signature into the certificate payload at offset `cert[126:]`.
- **Cryptographic Bounds Hardening**:
  - Validates private key deserialization with explicit error checking and safe comma-ok type assertions (`privKey, ok := key.(*mldsa65.PrivateKey)`).
  - Enforces strict slice boundary verification ensuring `len(signedCert) >= 126 + mldsa65.SignatureSize` before executing `mldsa65.SignTo`, preventing buffer slice panics.

---

## Module 3: Anti-Fingerprinting, Version Verification & TLS Record Parsing
- **Client Version Boundary Checks**:
  - Supported `MinClientVer` and `MaxClientVer` in `RealityConfig`.
  - Reality server parses the 3-byte client version embedded within the `ClientHello` SessionID and verifies it falls within `[MinClientVer, MaxClientVer]`, rejecting out-of-spec probes.
- **Normalized Version Parsing (`realityValue`)**:
  - Refactored `realityValue` to consistently evaluate version byte slices as `(major << 16) | (minor << 8) | patch` for all input lengths up to 3 bytes.
- **Big-Endian uint16 TLS Record Parsing Fix**:
  - Parsed 2-byte TLS record version (`s2cSaved[1:3]`) and record length (`s2cSaved[3:5]`) using `binary.BigEndian.Uint16`, preventing length-dependent bit-shift bugs when inspecting TLS records in `RealityServer`.

---

## Module 4: Chrome 155 & Chrome Root Store Trust Anchors
- **Chrome 155 (`HelloChrome_155`)**:
  - Backported fresh macOS capture for Chrome 155.0.8059.40 from `refraction-networking/utls:master`.
  - Updated `HelloChrome_Auto` to default to `HelloChrome_155`.
- **Trust Anchors Extension (`u_trust_anchors.go`)**:
  - Implemented Chrome Root Store trust anchor IDs extension (`0xca34`) advertising 28 certificate identifier hashes matching modern Chromium TLS handshakes.
  - Registered `trust_anchors` in `dicttls/exttype_values.go` for JSON fingerprint serialization.

---

## Module 5: Certificate Decompression & Concurrency Hardening
- **Stream Termination & Trailing Byte Rejection**:
  - Hardened `decompressCert` with `io.ReadFull` across all codecs.
  - Validates stream completion and rejects trailing uncompressed/compressed data after certificate stream.
- **Session Cache Concurrency Safety**:
  - Shallow-copies `SessionState` immediately after retrieval from `ClientSessionCache` in `loadSession`, preventing data races when multiple goroutines share session entries.

---

## Module 6: Code Quality & Static Analysis Hardening
- **Control Flow Clarification (`reality.go`)**:
  - Resolved static analysis rule SA4004 by refactoring single-iteration `for` loops into expressionless `switch` blocks.
- **Testing Coverage**:
  - `TestRealityValue`, `TestRealityMldsa65CertSize`, `TestRealitySignMldsa65` in `reality_test.go`.
  - `TestChrome155CapturedClientHello`, `TestChrome155DefaultFingerprintRoundTrip`, `TestChrome155PresetOwnership`, `TestChrome155SignatureGREASESeed` in `u_chrome155_test.go`.
  - Full suite in `u_trust_anchors_test.go`.
  - `TestModernBrowserAutoDefaults`, `TestFirefox157MatchesCapture`, `TestFirefox157WithSNI` in `u_firefox157_test.go`.

---

## Module 7: Latest Browser Fingerprints Integration & Live Browser Verification
- **Mozilla Firefox 157 (`HelloFirefox_157`)**:
  - Captured from and verified against official Mozilla Firefox 157.0 (Linux x86_64, NSS).
  - Pruned obsolete CBC-mode ECDSA cipher suites (`TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA`, `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA`) matching current NSS security policy.
  - Group alignment: `X25519MLKEM768`, `X25519`, `CurveP256`, `CurveP384`, `CurveP521` (FFDHE groups removed from default ClientHello).
  - Key Shares: Reuses classical X25519 private key across both hybrid `X25519MLKEM768` and classical `X25519`, with secondary share for `CurveP256` (1,327 bytes total).
  - Modern extensions added: `session_ticket` (`35`) and `psk_key_exchange_modes` (`45`).
  - Set `HelloFirefox_Auto = HelloFirefox_157`.
  - Fixture recorded in `testdata/firefox157_clienthello.hex` with markdown documentation and automated regression tests in `u_firefox157_test.go`.
- **Google Chrome 155 (`HelloChrome_155`)**:
  - Verified against official Google Chrome 155.0.8059.79.
  - Confirmed 100% byte-for-byte fidelity across ciphers, groups, key shares, ML-DSA signatures, ALPS (`0x44cd`), BoringSSL GREASE ECH, and Chrome Root Store Trust Anchors (`0xca34`).
  - Set `HelloChrome_Auto = HelloChrome_155`.
- **Microsoft Edge 155 (`HelloEdge_155`)**:
  - Upgraded from obsolete Chromium 106 to modern Chromium 155 BoringSSL engine.
  - Parrots full modern Chromium fingerprint suite.
  - Set `HelloEdge_Auto = HelloEdge_155`.
- **Apple iOS 26.3 (`HelloIOS_26_3`)**:
  - Upgraded from legacy iOS 14 (2020) to current Apple Network.framework / CFNetwork / Security.framework TLS 1.3 spec.
  - Matches Safari 26.3 with `X25519MLKEM768` post-quantum key exchange, GREASE, and modern cipher ordering.
  - Set `HelloIOS_Auto = HelloIOS_26_3`.
