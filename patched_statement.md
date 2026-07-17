# Patch Statement: ML-DSA-65 and MasterKeyLog Backport

This branch (`patch-reality-v26`) contains backported security features from Xray-core `v26.7.11`'s `xtls/reality` implementation to `metacubex/utls`.

## Features Ported
1. **Post-Quantum Authentication (ML-DSA-65)**:
   - Added `Mldsa65Verify` and `Mldsa65Seed` (compiles to `Mldsa65Key`) to `RealityConfig`.
   - Imported `github.com/cloudflare/circl/sign/mldsa/mldsa65`.
   - Server-side signature injection into `cert[126:]` during TLS 1.3 handshake.
   - Client-side signature extraction and verification.
2. **Secure Key Logging (`MasterKeyLog`)**:
   - Added `MasterKeyLog func(format string, v ...any)` to `RealityConfig`.
   - Designed to allow administrators to safely dump TLS master secrets (e.g., `CLIENT_RANDOM`) for Wireshark analysis without exposing sensitive variables in standard console logs.

## Purpose
This patch brings `utls` into full security parity with upstream Xray-core `v26.7.11`, protecting against harvest-now-decrypt-later MITM attacks via hybrid key exchange and post-quantum certificate signatures.

*Authored for the mihomo-mine v26 migration.*

---

## Code Quality & Static Analysis Fixes

1. **Unconditionally Terminated Loops (`reality.go`)**:
   - Fixed static analysis warnings (rule SA4004) where single-iteration `for` loops were used as simple blocks to allow early exits via `break`. 
   - Refactored these structures into expressionless `switch` blocks (e.g., `switch { default:` and `switch { case peerPub != nil:`). This preserves the identical control flow while eliminating the loop-related warnings.
2. **Redundant Return Statements (`u_alias.go`)**:
   - Fixed static analysis warnings (rule S1023) by removing redundant `return` statements from the empty functions `AddEcdheKeypair` and `AddKemKeypair`.
