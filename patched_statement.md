# Patch Statement: utls (v1.9.0-patch3)

This document describes the functional and architectural changes introduced in branch `main-patched` of `zhfreal/utls` on top of upstream `metacubex/utls v1.9.0-mod-meta` and backported features from `refraction-networking/utls:master`, `bogdanfinn/utls`, and modern browser ecosystem captures.

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
  - `TestNewOnlineFingerprintPresets`, `TestMultiKeyShareCycling` in `u_parrots_new_test.go`.
  - `TestMLDSAVerifyHandshakeSignature`, `TestMLDSAVerifyRejectsNonMLDSAKey`, `TestMLDSATypeAndHash`, `TestMLDSAIsSignatureScheme`, `TestMLDSASchemeRecoveryFromSPKI` in `mldsa_test.go`.

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

---

## Module 8: Online Repositories Integration: Modern Android, Brave, Opera, 360, QQ & Multi-KeyShare Cycling
- **Modern Android & OkHttp 4/5 (`HelloAndroid_14_OkHttp`, `HelloAndroid_15_OkHttp`, `HelloAndroid_Auto`)**:
  - Upgraded from obsolete TLS 1.2-only `HelloAndroid_11_OkHttp` to modern Conscrypt/OkHttp TLS 1.3 stack.
  - Supported: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, X25519 KeyShare, ALPN (`h2`, `http/1.1`), PskModeDHE, and BoringPaddingStyle.
  - Set `HelloAndroid_Auto = HelloAndroid_14_OkHttp`.
- **Brave Browser (`HelloBrave_146`, `HelloBrave_Auto`)**:
  - Implemented Brave Browser privacy suite matching real-world browser captures (`RandomExtensionOrder = true`).
  - Automatically randomizes non-GREASE extensions while preserving bookends, defeating extension-order fingerprinting.
  - Includes `X25519MLKEM768` hybrid post-quantum key agreement, ALPS, GREASE ECH, and Brotli compression.
  - Set `HelloBrave_Auto = HelloBrave_146`.
- **Opera Browser (`HelloOpera_136`, `HelloOpera_Auto`, `HelloOpera_91`, `HelloOpera_90`, `HelloOpera_89`)**:
  - Live captured authentic TLS ClientHello from locally installed Opera 136 (`136.0.6008.80`, Chromium 136 engine).
  - Integrated full modern Chromium BoringSSL fingerprint: `X25519MLKEM768` hybrid post-quantum key agreement, `MLDSA44`/`MLDSA65`/`MLDSA87` post-quantum signature schemes, `ApplicationSettingsExtensionNew` (`0x44cd` ALPS), `BoringGREASEECH`, and authentic 32 Trust Anchor IDs (`0xca34` Chrome Root Store).
  - Applied `ShuffleChromeTLSExtensions` to emulate Chromium extension order permutation.
  - Set `HelloOpera_Auto = HelloOpera_136`.
  - Added wire verification tests in `u_opera136_test.go` and fixture `testdata/opera136_clienthello.hex`.
- **360 Extreme Browser (`Hello360_122`, `Hello360_Auto`) & QQ Browser (`HelloQQ_123`, `HelloQQ_Auto`)**:
  - Upgraded 360 Browser from legacy versions 7.5 (2014) and 11.0 (2019) to modern Chromium 122+ engine (`Hello360_122`).
  - Upgraded QQ Browser from legacy version 11.1 (Chromium 89) to modern Chromium 123+ engine (`HelloQQ_123`).
  - Set `Hello360_Auto = Hello360_122` and `HelloQQ_Auto = HelloQQ_123`.
- **Dynamic Multi-KeyShare Cycling**:
  - Resolved TLS 1.3 handshake failures when servers select secondary key shares (e.g. `CurveP256` or fallback).
  - Maintained `Keys map[CurveID]*ecdh.PrivateKey` in `keySharePrivateKeys` and `KeySharePrivateKeys` to store all generated keys by group.
- **End-to-End ML-DSA Certificate Signature Verification**:
  - Implemented `mldsa.go` and `mldsa_circl.go` using CIRCL.
  - Recovered unparsed SPKI public keys from `RawSubjectPublicKeyInfo` via `circlpki.UnmarshalPKIXPublicKey`.
  - Dispatched `signatureMLDSA` directly to `verifyMLDSAHandshakeSignature` with direct signing.

---

## Post-Review Fixes & Design Improvements

1. **`UQUICConn` & `QUICConn` Session Safety and Preset Transport Parameters (`u_quic.go`, `quic.go`)**:
   - Added `SessionTicketsDisabled` check to `UQUICConn.SendSessionTicket` and nil `ClientSessionCache` / `SessionTicketsDisabled` guards to `UQUICConn.StoreSession` and `QUICConn.StoreSession` to prevent nil-pointer panics.
   - Restored propagation of `params` to `QUICTransportParametersExtension` in `UQUICConn.SetTransportParameters` when using custom ClientHello presets.
2. **Hybrid Post-Quantum KeyShare Preset Support (`u_parrots.go`)**:
   - Extended `classicalCurveForHybrid` and `ApplyPreset` (`KeyShareExtension`) to support `SecP256r1MLKEM768` and `SecP384r1MLKEM1024` alongside `X25519MLKEM768` and `X25519Kyber768Draft00`.
3. **Wildcard `ServerNames` Matching in `reality.go`**:
   - Added `matchRealityServerName` supporting exact match, `*`, and single-label wildcard (`*.example.com`) patterns in `utls/reality.go`.


---

## 13. Additional Post-Review Bug Fixes & Hardening

1. **QUIC Transport Parameters Propagation to Presets (`u_quic.go`, `u_tls_extensions.go`)**:
   - Enabled propagation of raw transport parameters in `UQUICConn.SetTransportParameters` and `QUICTransportParametersExtension.writeToUConn` into `qtp.marshalResult` whenever `len(qtp.TransportParameters) == 0`, regardless of whether `SetTransportParameters` is called before or after `ApplyPreset`.
2. **Multi-Hybrid KeyShare Private Key Lookup (`key_schedule.go`, `u_public.go`, `u_parrots.go`)**:
   - Added `MlkemKeys map[CurveID]mlkem.Decapsulator` (and `mlkemKeys`) to `KeySharePrivateKeys` / `keySharePrivateKeys` and updated `hybridKeyExchange.clientSharedSecret` to look up `priv.keys[ke.id]` and `priv.mlkemKeys[ke.id]` by the negotiated hybrid `CurveID` before falling back to `MlkemEcdhe` / `Mlkem`.
3. **Empty SNI Rejection in `matchRealityServerName` (`reality.go`)**:
   - Updated `matchRealityServerName` so an empty ClientHello SNI (`""`) does not match wildcard `"*"` unless `""` is explicitly enabled in `serverNames`.


### 6. Elimination of Unverified `InsecureSkipVerify` (`handshake_client.go`, `u_parrots_test.go`, `u_conn_test.go`, `u_firefox157_test.go`)
- Updated `verifyServerCertificate` in `handshake_client.go` to reject `InsecureSkipVerify == true` whenever both `VerifyPeerCertificate == nil` and `VerifyConnection == nil` (`tls: InsecureSkipVerify is disabled; must use VerifyPeerCertificate or VerifyConnection to verify peer certificates`), without adding duplicate configuration fields to `utls.Config`.
- Updated test helpers in `u_parrots_test.go`, `u_conn_test.go`, and `u_firefox157_test.go` to pair `InsecureSkipVerify: true` with explicit `VerifyPeerCertificate` / `VerifyConnection` callbacks.


## Five-Round Code Review & Remediation Addendum (2026-10-15)

- **Round 1 (Cryptography, SNI Wildcards & Handshake Concurrency)**:
  - `reality.go` (`NewRealityListener`): Fixed loop-variable data race on `c, err` in the spawned handshake goroutine and closed `tlsConn` if `l.conns` closes before channel send.
  - `reality.go` (`matchRealityServerName`): Added `realityWildcardRegexCache` (`sync.Map`) to support non-prefix wildcard patterns (e.g., `api-*.example.com`, `*.sub.*.example.com`) identically to `REALITY/common.go`.
  - `handshake_client.go`: Enforced peer certificate verification (`InsecureSkipVerify` rejected unless `VerifyPeerCertificate` or `VerifyConnection` is provided).
