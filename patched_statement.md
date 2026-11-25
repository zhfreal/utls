# Codebase Change Statement: utls

**Current Codebase:** `zhfreal/utls` (`main-patched`, Tag: `v1.9.0-patch15` / `v1.9.0+patch15`)  
**Original Upstream Baseline:** `MetaCubeX/utls` (Branch `v1.9.0-mod-meta`, Commit `89a07ad380e263f7c3b406a3f7beb2a70dea263c`, Tag: `v1.9.0-alpha.1`)  
**Repository Location:** `./utls-mine` (symlinked to `/home/robin/Source/clash/clash.meta/utls-mine`)  
**Status:** Production-Ready, Race-Verified (`go test -race ./...` passing 100%)

---

## 1. Executive Summary

This document specifies the complete architectural, cryptographic, performance, and memory-safety delta between the current codebase (`zhfreal/utls @ main-patched`) and the original upstream baseline (`MetaCubeX/utls @ v1.9.0-mod-meta`, commit `89a07ad380e263f7c3b406a3f7beb2a70dea263c`, tag `v1.9.0-alpha.1`).

The modifications against the original upstream codebase are organized into two principal categories:
1. **Type 1: New Features & Cryptographic Extensions**: Modern browser ClientHello fingerprint parrots (Chrome 155, Edge 155, Firefox 157, Opera 136, Opera 89–91, Brave 146, iOS 26.3, Android 14/15 OkHttp, 360 Browser 122, QQ Browser 123), TLS Trust Anchors extension (`0xca34`), end-to-end post-quantum ML-DSA (`MLDSA44`, `MLDSA65`, `MLDSA87`) certificate signature verification and SPKI public key recovery, multi-hybrid key share routing (`SecP256r1MLKEM768`, `SecP384r1MLKEM1024`, `X25519MLKEM768`), and REALITY server wildcard SNI & ML-DSA-65 certificate signing.
2. **Type 2: Bug Fixes, Concurrency, Memory Leak & Resource Usage Remediations**: Deep `RealityConfig.Clone()` preventing concurrent map read/write crashes, `realityListener` shutdown panic and socket leak elimination, capacity-preserving `realityS2CBufPool` and `realityServerBufPool` pooling, automatic reclamation of `c.hand` and `c.rawInput` (`bytes.Buffer`) across `UConn` and `RealityServer` handshakes and fallbacks, compressed certificate stream truncation/trailing-data validation, RFC 9460 ECH unknown-version skip compliance, thread-safe PRNG mutex synchronization, `Roller.Dial` socket leak cleanup, and zero-allocation hot-path optimizations.

---

## 2. New Features

### 2.1 Modern Browser Fingerprint Parrots (`u_common.go`, `u_parrots.go`, `u_chrome155.go`, `u_opera136.go`)
* **Chromium, Firefox, Mobile & Regional Browser Profiles**:
  - Added `HelloChrome_155` (and updated `HelloChrome_Auto`), `HelloEdge_155` (`HelloEdge_Auto`), `HelloFirefox_157` (`HelloFirefox_Auto`), `HelloOpera_136` (`HelloOpera_Auto`), `HelloOpera_89`, `HelloOpera_90`, `HelloOpera_91`, `HelloBrave_146` (`HelloBrave_Auto`), `HelloIOS_26_3` (`HelloIOS_Auto`), `HelloAndroid_14_OkHttp` (`HelloAndroid_Auto`), `HelloAndroid_15_OkHttp`, `Hello360_122` (`Hello360_Auto`), and `HelloQQ_123` (`HelloQQ_Auto`).
* **GREASE Signature Algorithm & Hybrid KeyShare Support**:
  - Extended GREASE seed generation (`ssl_grease_ech_config_id`, `ssl_grease_signature_algorithm`, `ssl_grease_seed_count`) so `SignatureAlgorithmsExtension` replaces `GREASE_PLACEHOLDER` entries with deterministic BoringSSL GREASE values while keeping the exported `GetBoringGREASEValue` signature backward-compatible.
  - Added hybrid post-quantum curve support for `SecP256r1MLKEM768` (P-256 + ML-KEM-768) and `SecP384r1MLKEM1024` (P-384 + ML-KEM-1024) alongside `X25519MLKEM768` and `X25519Kyber768Draft00` in `classicalCurveForHybrid` and `UConn.ApplyPreset`.

### 2.2 TLS Trust Anchors Extension (`0xca34`) (`u_trust_anchors.go`, `u_common.go`, `u_tls_extensions.go`, `dicttls/exttype_values.go`)
* **Draft Trust Anchor IDs Extension (`TrustAnchorsExtension`)**:
  - Implemented `TrustAnchorsExtension` (`utlsExtensionTrustAnchors = 0xca34`) with wire serialization (`Read`/`Write`), JSON unmarshaling, non-aliasing slice copying, and strict RFC length validation (each TrustAnchorID in `1..255` bytes, total extension payload `<= 65535` bytes).
  - Wired `chrome155TrustAnchorIDs()` (`u_chrome155.go`) and `opera136TrustAnchorIDs()` (`u_opera136.go`) into their respective browser presets.

### 2.3 Post-Quantum ML-DSA Signature Verification (`mldsa.go`, `mldsa_circl.go`, `auth.go`, `cache.go`, `common.go`, `handshake_client_tls13.go`)
* **Direct SPKI Public Key Recovery (`mldsa_circl.go`, `cache.go`)**:
  - Added `parseCertificate(der []byte)` in `mldsa_circl.go` and wired it into `certCache.newCert` (`cache.go`). When `x509.ParseCertificate` returns a certificate with a nil `PublicKey`, `parseCertificate` inspects `RawSubjectPublicKeyInfo` via `circlpki.UnmarshalPKIXPublicKey` to recover `ML-DSA-44`, `ML-DSA-65`, or `ML-DSA-87` public keys.
* **TLS 1.3 CertificateVerify Validation (`auth.go`, `handshake_client_tls13.go`)**:
  - Added `MLDSA44` (`0x0904`), `MLDSA65` (`0x0905`), and `MLDSA87` (`0x0906`) signature schemes with `directSigning` (no pre-hash) and `verifyMLDSAHandshakeSignature` in `auth.go` and `handshake_client_tls13.go`.

### 2.4 Multi-Hybrid KeyShare Private Key Routing (`key_schedule.go`, `u_public.go`, `u_parrots.go`)
* **Per-Group ECDHE & ML-KEM Key Maps**:
  - Extended `keySharePrivateKeys` and `KeySharePrivateKeys` with `keys`/`Keys map[CurveID]*ecdh.PrivateKey` and `mlkemKeys`/`MlkemKeys map[CurveID]mlkem.Decapsulator`.
  - Updated `ecdhKeyExchange.clientSharedSecretChooseEcdhe` and `hybridKeyExchange.clientSharedSecret` to resolve private keys by the server-selected `CurveID` before falling back to single-key fields, allowing ClientHellos advertising multiple classical and hybrid key shares simultaneously to complete handshakes for any server-selected group.

### 2.5 Embedded REALITY Wildcard SNI, ML-DSA-65 Signing & Tunable Timeouts (`reality.go`, `patch_reality_server.go`)
* **Wildcard ServerName Matching**:
  - Added `matchRealityServerName` supporting exact match, single-label suffix fast-path (`*.example.com`), general wildcard regex matching cached in `realityWildcardRegexCache` (`sync.Map`) keyed directly by raw `pattern` string (zero allocations on cache hit), and catch-all `"*"` (while rejecting empty SNI `""`).
* **Lazy ML-DSA-65 Server Certificate Template & Private Key Cache**:
  - Added `realityServerCertMldsa65` (`patch_reality_server.go`) lazily initialized via `onceValues` and `loadOrParseRealityMldsa65PrivateKey` (`reality.go`) caching parsed `*mldsa65.PrivateKey` instances in `realityMldsa65KeyCache` (`sync.Map`) keyed by stack-allocated `[32]byte` SHA-256 digests (`sha256.Sum256(raw)`).
* **Tunable Timeouts & Named Protocol Constants**:
  - Added `HandshakeTimeout` and `FallbackReadDeadline` to `RealityConfig` and defined named constants in `reality.go` and `u_roller.go` (`realityIndexServerHello`..`realityIndexNewSessionTicket`, `realityChangeCipherSpecRecordLen`, `realityChangeCipherSpecPayloadByte`, `realityEncryptedExtensionsMinLen`, `realityAuthKeyHKDFSaltLen`, `realityAuthKeyLen`, `realitySessionIDLen`, `realityClientTimeOffset`, `realityClientShortIDOffset`, `realityX25519KeyLen`, `realityMldsa65CertSignatureOffset`, `realityDefaultHandshakeTimeout`, `realityFallbackReadDeadline`, `realityClientVerLen`, `realityShortIDLen`, `realityProbeBufLen`, `realityRecordVerStart`/`End`, `realityRecordLenStart`/`End`, `RollerMinTcpDialTimeoutSecs`..`RollerRandomTlsHandshakeSpanSecs`).

---

## 3. Bug Fixes, Memory Leak & Resource Usage Remediations

### 3.1 Handshake Buffer Reclamation & Scratch Buffer Pooling (`reality.go`, `u_conn.go`)
* **Reclamation of `c.hand` and `c.rawInput` (`bytes.Buffer`) Across `UConn` and `RealityServer` (`reality.go`, `u_conn.go`)**:
  - Upstream `Conn` retained `c.hand` (which grows to 4–16 KiB to buffer the peer's Certificate chain or ClientHello) and `c.rawInput` for the entire lifetime of every TLS connection, and `RealityServer` retained `hs.c.hand` and `hs.c.rawInput` across long-lived fallback `io.Copy` sessions.
  - Added `(*Conn).releaseHandshakeBuffers(force bool)` in `reality.go` and wired it into `(*UConn).handshakeContext`, `(*UConn).Read`, and `RealityServer`:
    - On successful client (`UConn`) or server (`RealityServer`) handshake completion, empty `c.hand` and `c.rawInput` buffers are reset to `bytes.Buffer{}` so established connections do not pin multi-kilobyte handshake buffers while idle.
    - In `(*UConn).Read`, `c.hand` is reset to `bytes.Buffer{}` after consuming post-handshake messages (such as `NewSessionTicket`).
    - In `RealityServer`, when falling back (`hs.c.conn != conn`) or when the handshake fails, `hs.c.releaseHandshakeBuffers(true)` immediately frees `c.hand`, `c.rawInput`, and `c.out.handshakeBuf` before entering fallback `io.Copy` or closing `conn`; `(*UConn).handshakeContext` also calls `c.releaseHandshakeBuffers(true)` whenever `c.handshakeErr != nil`.
* **16 KiB Target Scratch & Server-to-Client Buffer Pools (`reality.go`)**:
  - Pooled the 16 KiB `buf` (`realityServerBufPool`) and 16 KiB `s2cSaved` (`realityS2CBufPool`) buffers in `RealityServer`, eliminating 32 KiB of heap allocations per incoming connection.
  - Kept the pooled `s2cBufPtr` slice header unmodified (`s2cSaved := (*s2cBufPtr)[:0]` with `defer realityS2CBufPool.Put(s2cBufPtr)`) so reslicing `s2cSaved = s2cSaved[handshakeLen:]` during record consumption never shrinks the pooled buffer's capacity or escapes a slice header to the heap.
* **Dedicated `handshakeBuf` & Safe Target Drain (`reality.go`)**:
  - Allocated a dedicated `make([]byte, 0, handshakeLen)` slice for `hs.c.out.handshakeBuf` instead of aliasing `buf[:0]`, and passed `remaining := handshakeLen - len(s2cSaved)` by value to the drain goroutine using `io.CopyN(io.Discard, target, int64(remaining))` and a stack `probeBuf [1]byte`.
* **Stack-Allocated SessionID Buffers, Fast-Filter & Fallback Restoration (`reality.go`)**:
  - Added `len(hs.clientHello.sessionId) == realitySessionIDLen` (32 bytes) pre-check before X25519 ECDH, HKDF, and AES-GCM.
  - Replaced heap-allocated `make([]byte, 32)` buffers with stack-allocated `var ciphertext, plainText [realitySessionIDLen]byte` and restored `copy(hs.clientHello.sessionId, ciphertext[:])` unconditionally after `aead.Open` so `hs.clientHello.original` is never left zeroed on fallback connections.

### 3.2 REALITY Deep Config Cloning, Listener Shutdown Safety & Handshake Deadlines (`reality.go`)
* **Deep Configuration Cloning (`RealityConfig.Clone`)**:
  - Deep-cloned `ServerNames`, `ShortIds`, `PrivateKey`, `MinClientVer`, `MaxClientVer`, `Mldsa65Verify`, and `Mldsa65Key` under `a.Config.mutex.RLock()`, preventing `concurrent map read and map write` crashes.
* **Listener Panic & Socket Leak Elimination (`realityListener`)**:
  - Replaced `close(l.conns)` on accept error with a `done chan struct{}` closed via `closeOnce sync.Once`, a listener-scoped `ctx` / `cancel`, and `errMu sync.Mutex`.
  - Handshake workers select on `case l.conns <- tlsConn:` vs `case <-l.done: _ = tlsConn.Close()`, recover panics by closing `tlsConn` or raw `conn`, and `Close()` drains any buffered connections from `l.conns`.
* **Handshake Deadlines, Context Watchdog & Symmetrical Fallback Teardown**:
  - Propagated caller `ctx` into `hs.ctx`, `readClientHello(ctx)`, and a `context.AfterFunc` watchdog closing `target` and `conn` on cancellation.
  - Applied `HandshakeTimeout` (default `10s`) to `conn` and `target` during the handshake and `FallbackReadDeadline` (default `5s`) after `CloseWrite()` in both fallback directions (`underlying -> target` and `target -> underlying`) so half-open sockets cannot leak goroutines.
* **TLS 1.3 Cryptographic Bounds, Nil Safety & Semantic Version Alignment**:
  - Added nil, length, and error checks on `RealityConfig.Clone()`, `newRateLimitedConn`, `RealityServer` (`conn`, `config`, `config.DialContext`), `hs.suite`, `aes.NewCipher`/`cipher.NewGCM`, `peerData`, `hs.hello.serverShare.data`, `generateECDHEKey`, `NewPublicKey`, `key.ECDH`, `mlkem.NewEncapsulationKey768`, and `signedCert` ML-DSA-65 signature offset, and replaced `append(ciphertext, ...)` with two direct `copy()` calls.
  - Aligned `realityValue(vals ...byte)` to fixed major/minor/patch bit positions `(vals[i] << ((2 - i) * 8))` and checked `len(MinClientVer) == 0` / `len(MaxClientVer) == 0`.

### 3.3 Compressed Certificate Validation & ECH RFC 9460 Compliance (`u_handshake_client.go`, `ech.go`)
* **Strict Certificate Decompression Stream Verification (`u_handshake_client.go`)**:
  - Replaced single `decompressed.Read(rawMsg[4:])` in `decompressCert` with `io.ReadFull(decompressed, rawMsg[4:])`, verified that reading one additional byte (`var extra [1]byte`) returns `0, io.EOF` (detecting excess decompressed output or deferred decoder errors), and verified `compressed.Len() == 0` (rejecting trailing bytes after the compressed stream).
* **RFC 9460 Unknown-Version ECH Config Skip & Zero-Copy ECH Parsing (`ech.go`)**:
  - Fixed `Conn.processECHClientHello` so `skip == true` from `parseECHConfig` (unknown ECH version) skips the key rather than aborting with `alertInternalError`.
  - Removed the intermediate `make([]byte, len(ext))` copy in `parseECHExt` and replaced `bytes.Replace` with `bytes.Clone` + `clear()` and a `len(hello) < 4` bounds guard in `decryptECHPayload`.

### 3.4 Thread-Safe PRNG, `Roller.Dial` Leak Fix, QUIC Guards & Hot-Path Allocations (`u_prng.go`, `u_roller.go`, `u_quic.go`, `quic.go`, `u_conn.go`, `jls.go`, `tls.go`)
* **PRNG Mutex Synchronization & Overflow-Safe Range/Coin Helpers (`u_prng.go`, `u_roller.go`)**:
  - Added `randMutex sync.Mutex` to `prng` protecting `Intn`, `Int63n`, `Perm`, and `Roller.Dial`'s `Shuffle`; added `NaN`/`<=0`/`>=1` fast paths in `FlipWeightedCoin` and `uint64` span arithmetic preventing signed overflow in `prng.Range`.
* **Socket Cleanup & Guards on `Roller.Dial` (`u_roller.go`)**:
  - Guarded `Roller.Dial` against nil `r`, empty `r.HelloIDs`, and non-positive `r.TlsHandshakeTimeout`, added `_ = client.Close()` when `client.Handshake()` fails in `Roller.Dial`, and copied `client.ClientHelloID` by value into `c.WorkingHelloID`.
* **QUIC / UQUIC Session Cache, Close Cleanup & Transport Parameter Guards (`u_quic.go`, `quic.go`, `u_tls_extensions.go`)**:
  - Guarded `SendSessionTicket` and `StoreSession` against `SessionTicketsDisabled` and nil `ClientSessionCache`, added nil guards and buffer clearing (`events`/`readbuf`) in `UQUICConn.Close`, and propagated `q.conn.quic.transportParams` into `QUICTransportParametersExtension.marshalResult` when `TransportParameters` is empty.
* **Hot-Path Allocation Reductions, Bounds & Nil Guards (`u_conn.go`, `jls.go`, `tls.go`, `u_trust_anchors.go`)**:
  - Reused a single dynamically sized `scratch` slice across `UConn.extensionsList()` (clearing headers and guarding `n >= 2`), released handshake buffers on error in `UConn.handshakeContext`, guarded `c.conn.Close()` against nil in `UConn.handshakeContext`, propagated `computeAndUpdateOuterECHExtension` errors in `MarshalClientHello`, bounded `jlsBuildFakeRandom` to 64 attempts with nil-RNG check and `clear(b)` in `jls.go`, cached `totalLen` in `TrustAnchorsExtension.Read`, and converted `timeoutError` methods to pointer receivers `(*timeoutError)` in `tls.go`.

---

## 4. File Modification & Addition Matrix

| File Path | Status | Change Category | Description of Delta Relative to Upstream Baseline (`89a07ad3`) |
| :--- | :--- | :--- | :--- |
| `u_chrome155.go` / `u_chrome155_test.go` | **Added** | **Features & Testing** | Chrome 155 Trust Anchor IDs and captured wire-format / ML-DSA tests. |
| `u_opera136.go` / `u_opera136_test.go` | **Added** | **Features & Testing** | Opera 136 Trust Anchor IDs and captured wire-format tests. |
| `u_firefox157_test.go` / `u_parrots_new_test.go` | **Added** | **Testing** | Unit tests for Firefox 157 and new browser fingerprint parrots. |
| `u_trust_anchors.go` / `u_trust_anchors_test.go` | **Added** | **Features & Testing** | `TrustAnchorsExtension` (`0xca34`) implementation, cached `totalLen`, bounds validation, and tests. |
| `dicttls/exttype_values.go` | **Modified** | **Features** | Registered `ExtType_trust_anchors` (`0xca34`). |
| `u_common.go` / `u_parrots.go` | **Modified** | **Features & Perf** | New browser presets (Chrome 155, Edge 155, Firefox 157, Opera 136/89–91, Brave 146, iOS 26.3, Android 14/15, 360 122, QQ 123), hybrid PQ curves (`SecP256r1MLKEM768`, `SecP384r1MLKEM1024`), stack GREASE seed buffer, and per-curve key map population. |
| `mldsa.go` / `mldsa_circl.go` / `mldsa_test.go` | **Added** | **Features & Testing** | CIRCL-based `ML-DSA-44/65/87` signature verification, SPKI public key recovery, and tests. |
| `auth.go` / `cache.go` / `common.go` / `handshake_client_tls13.go` | **Modified** | **Features** | Wired `signatureMLDSA` and `parseCertificate` into TLS 1.3 certificate verification. |
| `key_schedule.go` / `u_public.go` | **Modified** | **Features** | Per-curve `keys` and `mlkemKeys` maps on `keySharePrivateKeys` / `KeySharePrivateKeys`. |
| `reality.go` / `patch_reality_server.go` / `reality_test.go` | **Modified / Added** | **Features, Memory & Concurrency** | Wildcard SNI, `realityMldsa65KeyCache`, deep `RealityConfig.Clone()` (with nil check), `newRateLimitedConn`/`hs.suite`/`RealityServer` nil & cipher/GCM error checks, `realityListener` shutdown safety, `realityServerBufPool` and capacity-preserving `realityS2CBufPool` (16 KiB), `releaseHandshakeBuffers` freeing `c.hand`/`c.rawInput`, stack `[32]byte` buffers, handshake/fallback deadlines, and unit tests. |
| `u_conn.go` | **Modified** | **Memory & Bugfix** | `releaseHandshakeBuffers(false)` on handshake completion, `releaseHandshakeBuffers(true)` on error, `c.hand` reclamation in `Read`, reusable `scratch` buffer with `clear`/`n >= 2` guard in `extensionsList()`, ECH error propagation, and nil `c.conn` guard in `handshakeContext`. |
| `u_handshake_client.go` | **Modified** | **Security / Bugfix** | `io.ReadFull`, excess decompressed byte check, and trailing compressed data check in `decompressCert`. |
| `ech.go` / `ech_test.go` | **Modified** | **Bugfix & Perf** | RFC 9460 unknown-version ECH config skip fix, zero-copy `parseECHExt`, single-allocation `decryptECHPayload`. |
| `u_prng.go` / `u_roller.go` | **Modified** | **Concurrency & Leak Fix** | `randMutex` protecting `math/rand.Rand`, `FlipWeightedCoin` `NaN`/`<=0`/`>=1` fast paths, `uint64` span in `Range`, `Roller.Dial` nil/empty/timeout guards, `_ = client.Close()` on failed handshake, value-copied `WorkingHelloID`, and named timeout constants. |
| `u_quic.go` / `quic.go` / `u_tls_extensions.go` | **Modified** | **Bugfix** | Nil `ClientSessionCache` and `SessionTicketsDisabled` guards, `UQUICConn.Close` nil guards & buffer clearing, QUIC transport parameter propagation, and GREASE seed bounds check. |
| `jls.go` / `tls.go` / `handshake_test.go` | **Modified** | **Perf & Quality** | 64-attempt/nil-RNG bound and `clear(b)` in `jlsBuildFakeRandom`, stack buffers and hash reuse in `jls.go`, pointer receiver on `timeoutError` in `tls.go`, and race fix in `handshake_test.go`. |
