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
