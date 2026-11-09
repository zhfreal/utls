# Codebase Change Statement: utls

**Current Codebase:** `zhfreal/utls` (`main-patched`, Tag: `v1.9.0-patch11` / `v1.9.0+patch11`)  
**Original Upstream Baseline:** `MetaCubeX/utls` (Branch `v1.9.0-mod-meta`, Git Commit `a6a364afbd13015e2d6da7d55f8ad4123f9fc0b9`)  
**Repository Location:** `./utls-mine` (symlinked to `/home/robin/Source/clash/clash.meta/utls-mine`)  
**Status:** Production-Ready, Race-Verified (`go test -race ./...` passing 100%)

---

## 1. Executive Summary

This document specifies the complete architectural, cryptographic, and performance delta between the current codebase (`zhfreal/utls @ main-patched`) and the original upstream baseline (`MetaCubeX/utls @ v1.9.0-mod-meta`).

The modifications are structured into two distinct categories:
1. **Type 1: New Features & Cryptographic Extensions**: Live browser ClientHello fingerprint parrots (Opera 136, Chrome 155, Firefox 157), end-to-end post-quantum ML-DSA signature verification with direct SPKI public key extraction, embedded server-side REALITY negotiation engine, and multi-hybrid keyshare routing.

- **Named Default Constants for All Tunable Parameters (`u_common.go`, `u_conn.go`, `u_fingerprinter.go`, `u_session_controller.go`)**: Formalized all added and modified buffer sizes, slice lengths, cache limits, and extension capacities (`DefaultSessionTicketMaxBytes`, `DefaultFingerprinterMaxAlpnLen`, `DefaultInitialKeyShareCap`, `DefaultClientHelloPadAlign`, `DefaultPSKIdentitiesCap`, `DefaultCipherSuitesCap`) as named `const` default definitions with zero inline magic numbers.
2. **Type 2: Bug Fixes, Concurrency & Memory Safety Remediations**: Elimination of concurrent map read/write crashes via deep configuration cloning, listener panic elimination on shutdown (`send on closed channel`), handshake memory aliasing fixes, thread-safe PRNG synchronization protecting LFSR state, TCP socket leak elimination on handshake failure, and hot-path zero-allocation refactoring.

---

## 2. New Features

### 2.1 Modern Browser Fingerprint Parrots (`u_parrots.go`, `u_opera136.go`, `u_chrome155.go`)
* **Opera 136 Live Profile (`HelloOpera_136`)**:
  - Implemented exact ClientHello byte sequence captured from Opera 136 (`u_opera136.go`).
  - Includes modern extension ordering, `X25519MLKEM768` hybrid post-quantum key shares, ML-DSA trust anchors, ALPN, and GREASE extensions.
* **Chrome 155 & Firefox 157 Profiles**:
  - Added `HelloChrome_155` and `HelloFirefox_157` matching modern browser TLS 1.3 handshakes.
  - Added hybrid post-quantum curve support (`SecP256r1MLKEM768`, `SecP384r1MLKEM1024`, and `X25519MLKEM768`) in `u_parrots.go`.

### 2.2 Post-Quantum ML-DSA Signature Verification (`mldsa.go`, `mldsa_circl.go`)
* **Direct SPKI Public Key Recovery**:
  - Implemented PKIX public key unmarshaling from `RawSubjectPublicKeyInfo` via `circlpki.UnmarshalPKIXPublicKey` in `mldsa_circl.go`.
  - Recovers unparsed SPKI public keys for ML-DSA-44, ML-DSA-65, and ML-DSA-87 without requiring Go runtime standard library support.
* **Handshake Signature Verification**:
  - Wired `signatureMLDSA` directly to `verifyMLDSAHandshakeSignature`, verifying post-quantum certificate signatures during TLS 1.3 handshakes.

### 2.3 Embedded REALITY Protocol Engine & Wildcard SNI (`reality.go`)
* **Embedded REALITY Protocol Engine**:
  - Integrated server-side REALITY negotiation and listener infrastructure (`RealityConfig`, `NewRealityListener`).
  - Supported exact match, single-label wildcard (`*.example.com`), and catch-all (`*`), backed by `realityWildcardRegexCache` (`sync.Map`).
  - Cached parsed ML-DSA-65 private keys in `realityMldsa65KeyCache` (`sync.Map`) keyed by stack-allocated SHA-256 digests (`[32]byte`) via `loadOrParseRealityMldsa65PrivateKey` to eliminate per-handshake key unmarshaling and eliminate 4KB string heap allocations.
* **Half-Close Fallback Handling & Stalled Session Teardown**:
  - Added `CloseWrite()` / `target.Close()` handling on fallback upload and download completion matching REALITY core specifications.
  - Implemented a 5-second read deadline grace period on fallback download completion, ensuring hung half-closed client sockets terminate cleanly and preventing indefinite goroutine and socket leaks.

### 2.4 Multi-Hybrid KeyShare Private Key Routing (`key_schedule.go`, `u_public.go`)
* **Multi-Curve Routing**:
  - Extended `KeySharePrivateKeys` with `MlkemKeys map[CurveID]mlkem.Decapsulator`.
  - Updated `hybridKeyExchange.clientSharedSecret` to look up decapsulators by negotiated hybrid `CurveID` before falling back to default keys, enabling seamless multi-curve hybrid negotiations.

---

## 3. Bugfixes

### 3.1 REALITY Concurrent Map Read/Write & Key Share Bounds Remediations (`reality.go`)
* **Deep Configuration Cloning (`RealityConfig.Clone`)**:
  - In upstream, `RealityConfig` shallow-copied maps (`ServerNames`, `ShortIds`) and slices (`PrivateKey`, `MinClientVer`, `MaxClientVer`, `Mldsa65Verify`, `Mldsa65Key`). Concurrent modifications on cloned configs produced fatal runtime crashes: `fatal error: concurrent map read and map write`.
  - Implemented full deep cloning of all maps and slices under `a.Config.mutex.RLock()`.
* **TLS 1.3 Key Share Validation & Target Connection Nil Check**:
  - Added guards for nil `peerData`, slice bounds validation for `X25519MLKEM768`, nil checks on `peerKey` and `k`, and proper error handling for `generateECDHEKey`, `NewPublicKey`, `key.ECDH`, and `mlkem.NewEncapsulationKey768`, eliminating potential panics on invalid key shares.
  - Added defensive check `if target == nil` after `config.DialContext` in `RealityServer()`, preventing nil pointer panics on custom dialers.
  - Added `context.AfterFunc(ctx, ...)` cancellation watchdog in `RealityServer()` to immediately close `target` and `conn` if the caller's context is cancelled.
  - Enforced active handshake deadline watchdog (`realityDefaultHandshakeTimeout = 10s`) across both `conn` and `target` in `RealityServer()`, clearing deadlines upon successful handshake completion or fallback transition. This eliminates hung handshakes and permanently leaked goroutines when remote clients or target servers stall during the initial TLS exchange.
  - Optimized `X25519MLKEM768` server share assembly with zero-allocation in-place copy (`copy(data[:1088], ciphertext)` and `copy(data[1088:], key)`), eliminating intermediate 1.1 KiB heap slice allocations per handshake.

### 3.2 REALITY Listener Panic Elimination on Shutdown & Defensive Socket Teardown (`reality.go`)
* **Elimination of `panic: send on closed channel` & Descriptor Leaks**:
  - In upstream, `listener.Accept()` closed channels on the first error. Concurrent background handshake worker goroutines executing `l.conns <- tlsConn` then panicked with unrecoverable `send on closed channel`.
  - Replaced raw channel closure with a `done chan struct{}` closed once via `closeOnce sync.Once`. Handshake workers now select on `case l.conns <- tlsConn: case <-l.done: _ = tlsConn.Close()`.
  - Added defensive `recover()` teardown closing `conn` if a panic occurs before `tlsConn` assignment, preventing socket descriptor leaks on abrupt worker termination.

### 3.3 Handshake Memory Aliasing & Buffer Corruption Elimination (`reality.go`)
* **Dedicated Handshake Backing Buffer**:
  - Allocated a dedicated backing slice `make([]byte, 0, handshakeLen)` for `hs.c.out.handshakeBuf` instead of aliasing `buf[:0]`, preventing memory corruption from concurrent `target.Read(buf)` calls.
  - Reduced initial `s2cSaved` buffer allocation from 16 KiB to 4 KiB.
  - Passed `remaining` by value and used stack-allocated `probeBuf [1]byte` in the post-handshake target drain goroutine.

### 3.4 Thread-Safe PRNG & LFSR State Protection (`u_prng.go`)
* **PRNG Mutex Synchronization**:
  - Added `randMutex sync.Mutex` in `prng` to serialize access to `p.rand.Intn`, `p.rand.Int63n`, `p.rand.Perm`, and `p.rand.Shuffle`.
  - Eliminates state corruption in `math/rand.Rand` under concurrent dialing.

### 3.5 Socket & Goroutine Cleanup on Handshake Failure (`u_roller.go`)
* **Immediate Socket Teardown**:
  - In `Roller.Dial()`, added `_ = client.Close()` when `client.Handshake()` fails, preventing physical TCP file descriptors and buffered TLS structures from lingering in the system.
  - Safely cloned `client.ClientHelloID` into `c.WorkingHelloID` by value instead of retaining pointers into transient connection structures.

### 3.6 QUIC / UQUIC Nil-Pointer Panics & Parameter Propagation (`u_quic.go`, `quic.go`)
* **Nil-Pointer Panic Guards**:
  - Added `SessionTicketsDisabled` validation before calling `UQUICConn.SendSessionTicket`.
  - Added nil `ClientSessionCache` and `SessionTicketsDisabled` guards in `UQUICConn.StoreSession` and `QUICConn.StoreSession`.
* **Transport Parameter Propagation Across Presets**:
  - Enabled raw transport parameters in `UQUICConn.SetTransportParameters` and `QUICTransportParametersExtension.writeToUConn` to propagate into `qtp.marshalResult` whenever `len(qtp.TransportParameters) == 0`.

### 3.7 Hot-Path Zero-Allocation Optimizations (`u_conn.go`, `jls.go`)
* **Extension List Scratch Buffer Reuse (`u_conn.go`)**:
  - In `UConn.extensionsList()`, replaced per-extension `make([]byte, 2000)` allocations with a single reusable `scratch []byte` slice, dynamically expanding only if an extension exceeds the initial capacity.
  - Propagated errors returned by `computeAndUpdateOuterECHExtension` in `MarshalClientHello`.
* **JLS Authentication Optimization (`jls.go`)**:
  - In `jlsBuildFakeRandom` and `jlsCheckFakeRandom`, reused a single `sha256` instance via `h.Reset()` and `io.WriteString`, avoiding string-to-byte heap conversions.
  - Replaced heap allocations for `nonce`, `key`, and decrypted plaintext with stack-allocated `[32]byte` and `[jlsRandomSeedLen]byte` arrays, eliminating 7 heap allocations per JLS authentication attempt.

### 3.8 Test Harness Race Condition Remediation (`handshake_test.go`)
* **Local Error Scoping in Client Handshake Goroutine**:
  - In `testUtlsHandshake`, scoped `presetErr := ucli.ApplyPreset(spec)` within the client handshake goroutine rather than assigning directly to the outer return variable `err`, eliminating data races reported by `-race` between the client and server handshake routines.

### 3.9 Scratch Buffer Memory Pooling & Context Propagation (`reality.go`)
* **16 KiB Connection Scratch Buffer Pool**:
  - In upstream, `RealityServer()` allocated a 16 KiB scratch buffer (`buf := make([]byte, realitySize)`) on every incoming connection to read target ServerHello bytes. Under high concurrency, this generated excessive heap allocations.
  - Introduced `realityServerBufPool sync.Pool` with `defer realityServerBufPool.Put(bufPtr)` in the server handshake loop, completely eliminating per-connection heap allocations for ServerHello buffering.
* **Context Propagation & Handshake Cancellation**:
  - Wired caller-provided `ctx context.Context` into `hs.ctx` and `readClientHello(ctx)` rather than discarding it with `context.Background()`, ensuring caller cancellation and deadlines abort pending handshakes promptly.

### 3.11 Server Share Bounds Guard, Listener Handshake Cancellation, Stack GREASE Seed Allocation & Test Singleton Isolation (`reality.go`, `reality_test.go`, `u_parrots.go`, `u_tls_extensions.go`)
* **Bounds Validation on `X25519MLKEM768` Server Key Share (`reality.go`)**:
  - Verified `len(hs.hello.serverShare.data) >= mlkem.CiphertextSize768+realityX25519KeyLen` before copying the ML-KEM-768 ciphertext and X25519 public key into `hs.hello.serverShare.data`.
  - Checked `len(config.MinClientVer) == 0` and `len(config.MaxClientVer) == 0` in `RealityServer` so non-nil empty version slices do not evaluate to version `0` and reject valid clients.
* **Listener-Scoped Context Cancellation on Shutdown (`reality.go`)**:
  - Added a listener-scoped `context.Context` and `context.CancelFunc` to `realityListener` that is cancelled in `Close()` and passed to `RealityServer(l.ctx, conn, l.config)`, ensuring in-flight handshakes abort immediately when the listener shuts down.
* **Stack-Allocated GREASE Seed Buffer & Bounds Guard (`u_parrots.go`, `u_tls_extensions.go`)**:
  - Replaced heap-allocated `grease_bytes := make([]byte, 2*ssl_grease_seed_count)` in `u_parrots.go` with stack-allocated `var grease_bytes [2 * ssl_grease_seed_count]byte`, and added a defensive index bounds check in `getBoringGREASEValue`.
* **Singleton Certificate Isolation in `TestRealitySignMldsa65` (`reality_test.go`)**:
  - Cloned the singleton `signedCert` slice returned by `realityServerCertMldsa65()` before writing test signatures into `signedCert[126:]`, preventing concurrent tests from mutating the shared backing array.

### 3.10 Error Receiver Method Ambiguity Remediation (`tls.go`)
* **Pointer Receiver on `timeoutError`**:
  - In `tls.go`, `timeoutError` implemented `Error()`, `Timeout()`, and `Temporary()` with value receivers (`(timeoutError)`), causing both `timeoutError` and `*timeoutError` to implement `error` and `net.Error`, creating type-assertion ambiguity.
  - Converted the receiver to pointer `(*timeoutError)` so only `*timeoutError` implements `error`.

---

### 3.12 RFC 9460 ECH Unknown-Version Skip Compliance & Zero-Copy ECH Extension Parsing (`ech.go`)
* **Critical RFC 9460 Unknown-Version ECH Config Skip Fix (`ech.go`)**:
  - In `Conn.processECHClientHello`, the loop over `c.config.EncryptedClientHelloKeys` checked `if err != nil || skip` and returned `alertInternalError` whenever `skip == true`. Because `parseECHConfig` returns `skip = true, err = nil` for ECH configurations with an unrecognized version (as mandated by RFC 9460), any server configured with multiple ECH keys where one had a newer or unknown draft version aborted all ECH handshakes with `internal_error`.
  - Fixed the condition to `if err != nil` and added `if skip { continue }`, properly skipping unknown-version ECH configs while continuing to match valid keys.
* **Zero-Copy `parseECHExt` & Single-Allocation `decodeInnerClientHello` (`ech.go`)**:
  - Removed the redundant `data := make([]byte, len(ext)); copy(data, ext)` heap allocation in `parseECHExt`, parsing `cryptobyte.String(ext)` directly.
  - Replaced `bytes.Replace(hello[4:], payload, make([]byte, len(payload)), 1)` in `decodeInnerClientHello` with `bytes.Clone(hello[4:])` + in-place `clear(...)`, eliminating the temporary zero-slice heap allocation.

* **Nil `RemoteAddr()` Guard, Zero-Allocation Wildcard Regex Cache Lookup, Symmetrical Fallback Read Deadline & SessionID Integrity in `RealityServer` (`reality.go`)**:
  - Guarded `c.RemoteAddr()` against `nil` before calling `.String()` in `realityServerHandshakeStateTLS13.handshake()`, preventing nil-pointer panics when `RealityServer` runs over in-memory virtual pipes with logging enabled.
  - Keyed `realityWildcardRegexCache` in `matchRealityServerName` directly by `pattern` before calling `regexp.QuoteMeta` and `strings.ReplaceAll`, eliminating 3 heap string allocations on cache hits.
  - Set `_ = target.SetReadDeadline(time.Now().Add(fallbackReadDeadline))` after `target.CloseWrite()` on client-to-target fallback EOF so stalled destination servers cannot leak fallback goroutines or sockets.
  - Added `len(hs.clientHello.sessionId) == realitySessionIDLen` (32 bytes) pre-check before X25519 ECDH/HKDF/AES-GCM in `RealityServer` (`reality.go`) to skip cryptographic work on non-32-byte `SessionID` ClientHellos, and restored `copy(hs.clientHello.sessionId, ciphertext[:])` immediately after `aead.Open` on authentication failure so `hs.clientHello.sessionId` (aliased into `hs.clientHello.original`) is never left zeroed out on fallback connections.

---

## 4. File Modification & Addition Matrix

| File Path | Status | Change Type | Description of Delta Relative to Upstream Baseline |
| :--- | :--- | :--- | :--- |
| `u_opera136.go` | **Added** | **Type 1** (New Feature) | Opera 136 ClientHello preset definition and extension builder. |
| `u_opera136_test.go` | **Added** | Testing | Unit tests verifying Opera 136 wire format and ML-DSA trust anchors. |
| `u_chrome155.go` | **Added** | **Type 1** (New Feature) | Chrome 155 ClientHello preset definition and extension builder. |
| `u_chrome155_test.go` | **Added** | Testing | Unit tests verifying Chrome 155 captured wire format and ML-DSA compatibility. |
| `u_firefox157_test.go`| **Added** | Testing | Unit tests verifying Firefox 157 ClientHello against captured wire traffic. |
| `u_parrots.go` | **Modified** | **Type 1** (New Feature) | Hybrid post-quantum curve presets (`SecP256r1MLKEM768`, `SecP384r1MLKEM1024`, `X25519MLKEM768`), preset registry additions. |
| `key_schedule.go` | **Modified** | **Type 1** (New Feature) | Multi-hybrid `CurveID` routing in `hybridKeyExchange.clientSharedSecret`. |
| `mldsa.go` | **Added** | **Type 1** (New Feature) | ML-DSA algorithm constants and SPKI public key recovery interfaces. |
| `mldsa_circl.go` | **Added** | **Type 1** (New Feature) | CIRCL-based ML-DSA signature verification and public key unmarshaling. |
| `mldsa_test.go` | **Added** | Testing | Unit tests for ML-DSA-44, ML-DSA-65, and ML-DSA-87 signature verification and SPKI recovery. |
| `reality.go` | **Modified** | **Type 1** & **Type 2** | Type 1: Embedded REALITY engine, wildcard SNI, `realityMldsa65KeyCache`, safe `CloseWrite`, user-tunable `HandshakeTimeout` and `FallbackReadDeadline` fields on `RealityConfig`.<br>Type 2: Deep config cloning (`concurrent map read and write` fix), `done` channel listener panic elimination, unaliased `handshakeBuf`, stack arrays, zero-alloc SHA-256 key cache lookup, fallback read deadline teardown preventing stalled socket/goroutine leaks, `context.AfterFunc` cancellation watchdog, active handshake deadline enforcement (`realityDefaultHandshakeTimeout` and `realityFallbackReadDeadline`) preventing stalled goroutines, zero-alloc ML-KEM-768 server share assembly, `realityServerBufPool` 16KB and `realityS2CBufPool` 4KB scratch buffer pooling, caller `ctx` propagation in `RealityServer`, named protocol constants eliminating magic numbers in comparisons and slice bounds (`realityIndexNewSessionTicket`, `realityIndexServerHello`, `realityX25519KeyLen`, `realityClientVerLen`, `realityShortIDLen`, `realityProbeBufLen`, `realityRecordVerStart`/`realityRecordVerEnd`, `realityRecordLenStart`/`realityRecordLenEnd`). |
| `patch_reality_server.go` | **Added** | **Type 1** & **Type 2** | Type 1: Lazy initialization of REALITY ML-DSA-65 synthesized server certificate (`realityServerCertMldsa65`).<br>Type 2: Named constants `realityMldsa65CertPaddingLen` and `ed25519.PublicKeySize` eliminating magic literals. |
| `reality_test.go` | **Added** | Testing | Unit tests for REALITY value decoding, ML-DSA certificate sizing, and signature generation. |
| `u_prng.go` | **Modified** | **Type 2** (Bugfix) | Thread-safe `randMutex` protecting `math/rand.Rand` across all random generation methods. |
| `u_roller.go` | **Modified** | **Type 2** (Bugfix) | Closed leaked `tcpConn` on handshake failure in `Roller.Dial`, and defined named constants `RollerMinTcpDialTimeoutSecs`, `RollerRandomTcpDialTimeoutSpanSecs`, `RollerMinTlsHandshakeTimeoutSecs`, and `RollerRandomTlsHandshakeSpanSecs` eliminating magic literals. |
| `u_quic.go` | **Modified** | **Type 2** (Bugfix) | Transport parameter propagation across preset ClientHello generation, session cache guards. |
| `quic.go` | **Modified** | **Type 2** (Bugfix) | Nil `ClientSessionCache` and `SessionTicketsDisabled` guards in `StoreSession`. |
| `u_conn.go` | **Modified** | **Type 2** (Perf/Bugfix) | Reusable `scratch` buffer in `extensionsList()`, outer ECH error propagation in `MarshalClientHello`, defensive nil check in `handshakeContext` `contextAfterFunc` callback preventing panic when `UConn` or embedded `Conn` is nil. |
| `tls.go` | **Modified** | **Type 2** (Code Quality) | Converted `timeoutError` receiver methods to `*timeoutError` pointer receivers, resolving interface ambiguity. |
| `jls.go` | **Modified** | **Type 2** (Perf) | Reused `sha256` hash instance, `io.WriteString` string-to-byte avoidance, stack `[32]byte` arrays for nonce/key/plaintext. |
| `handshake_test.go` | **Modified** | **Type 2** (Bugfix) | Scoped error variable in client handshake goroutine to eliminate data race with server handshake. |
