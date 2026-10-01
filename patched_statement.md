# Patch Statement: utls (v1.8.8-patch4)

This document describes the functional and architectural changes introduced in branch `main-patched` of `zhfreal/utls` on top of the original upstream release `metacubex/utls v1.8.8`.

---

## Module 1: Post-Quantum Authentication (ML-DSA-65) Support

### 1. Context & Goal
Protect Reality TLS handshakes against harvest-now-decrypt-later MITM attacks by integrating post-quantum digital signatures into TLS 1.3 certificate exchanges in parity with Xray-core.

### 2. Implementation Details (`reality.go`, `patch_reality_server.go`, `go.mod`)
- **Configuration Fields**: Extended `RealityConfig` with:
  - `Mldsa65Verify (any)`: Client-side public key verification object (type `*mldsa65.PublicKey`).
  - `Mldsa65Key ([]byte)`: Server-side private key bytes for certificate signing.
- **Dependency Integration**: Integrated NIST FIPS 204 post-quantum module `github.com/cloudflare/circl/sign/mldsa/mldsa65` (v1.6.1).
- **Server Certificate Allocation & Signing**:
  - Implemented `realityServerCertMldsa65`: Allocates a server certificate structure formatted to accommodate the ML-DSA-65 signature size.
  - Implemented `realitySignMldsa65`: Cryptographically signs the TLS 1.3 server handshake context and injects the resulting signature into the certificate payload at offset `cert[126:]`.
- **Cryptographic Bounds Hardening**:
  - Validates private key deserialization with explicit error checking and safe comma-ok type assertions (`privKey, ok := key.(*mldsa65.PrivateKey)`).
  - Enforces strict slice boundary verification ensuring `len(signedCert) >= 126 + mldsa65.SignatureSize` before executing `mldsa65.SignTo`, preventing buffer slice panics.

---

## Module 2: Anti-Fingerprinting & Version Verification Hardening

### 1. Context & Goal
Defend Reality endpoints against active probing and TLS fingerprint classification while enforcing client version boundaries.

### 2. Implementation Details (`reality.go`)
- **Client Version Boundary Checks**:
  - Supported `MinClientVer` and `MaxClientVer` in `RealityConfig`.
  - Reality server parses the 3-byte client version embedded within the `ClientHello` SessionID and verifies it falls within `[MinClientVer, MaxClientVer]`, rejecting out-of-spec probes.
- **Normalized Version Parsing (`realityValue`)**:
  - Refactored `realityValue` to consistently evaluate version byte slices as `(major << 16) | (minor << 8) | patch` for all input lengths up to 3 bytes.
  - Eliminates length-dependent bit-shift skew where 1-byte or 2-byte inputs previously miscalculated version integers.

---

## Module 3: Master Key Logging Support (`KeyLogWriter`)

### 1. Context & Goal
Enable safe TLS master secret inspection for Wireshark network troubleshooting without leaking sensitive keys into standard console or application logs.

### 2. Implementation Details (`reality.go`)
- Exposed and wired the embedded `tls.Config.KeyLogWriter` within `RealityConfig`.
- Exports TLS master secrets (`CLIENT_RANDOM`) directly to the designated writer during Reality handshakes.

---

## Module 4: Code Quality & Static Analysis Hardening

### 1. Implementation Details (`reality.go`, `u_alias.go`, `handshake_test.go`)
- **Control Flow Clarification (`reality.go`)**:
  - Resolved static analysis rule SA4004 (unconditionally terminated single-iteration loops used for early exit).
  - Refactored control flow into expressionless `switch` blocks (e.g., `switch { default:` and `switch { case peerPub != nil:`), preserving identical early-break semantics without diagnostic warnings.
- **Redundant Return Removal (`u_alias.go`)**:
  - Removed redundant `return` statements from empty stub functions `AddEcdheKeypair` and `AddKemKeypair` (resolving rule S1023).
- **Scanner Error Inspection (`handshake_test.go`)**:
  - Added explicit `scanner.Err()` validation following token scanning loops.

---

## Module 5: Test Suite & Verification

Unit test coverage is provided in `reality_test.go`:
- **`TestRealityValue`**: Verifies bit-shifting logic for version parsing across various slice lengths (3-byte, 2-byte, 1-byte, and empty).
- **`TestRealityMldsa65CertSize`**: Validates certificate byte capacity sizing for ML-DSA-65 signature injection.
- **`TestRealitySignMldsa65`**: Verifies cryptographic signing at certificate offset 126 using ML-DSA-65 keys and signature generation.
