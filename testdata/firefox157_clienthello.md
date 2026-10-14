# Firefox 157 ClientHello fixture

`firefox157_clienthello.hex` is the complete first TLS record from a fresh HTTPS
connection made by official Mozilla Firefox 157.0 on Linux x86_64.

The record is 1,869 bytes; its ClientHello handshake body is 1,864 bytes.

## Captured Profile Details
- **Cipher Suites**: 15 suites (CBC-mode ECDSA suites `0xc02c`/`0xc028` removed in modern NSS; CBC-mode RSA retained for legacy servers).
- **Supported Groups**: `X25519MLKEM768` (`0x11ec`), `X25519` (`0x001d`), `CurveP256` (`0x0017`), `CurveP384` (`0x0018`), `CurveP521` (`0x0019`). FFDHE groups removed from default ClientHello.
- **Key Share**: 1,327 bytes with shares for `X25519MLKEM768`, `X25519` (reusing the same classical X25519 public key as hybrid), and `CurveP256`.
- **Signature Schemes**: `ECDSAWithP256AndSHA256`, `ECDSAWithP384AndSHA384`, `ECDSAWithP521AndSHA512`, `PSSWithSHA256`, `PSSWithSHA384`, `PSSWithSHA512`, `PKCS1WithSHA256`, `PKCS1WithSHA384`, `PKCS1WithSHA512`, `ECDSAWithSHA1`, `PKCS1WithSHA1`.
- **Certificate Compression**: Zlib (`1`), Brotli (`2`), Zstd (`3`).
- **Extensions & Ordering**:
  1. `extended_master_secret` (`23`) (preceded by `server_name` (`0`) when SNI is configured)
  2. `renegotiation_info` (`65281`)
  3. `supported_groups` (`10`)
  4. `ec_point_formats` (`11`)
  5. `session_ticket` (`35`)
  6. `application_layer_protocol_negotiation` (`16`)
  7. `status_request` (`5`)
  8. `delegated_credentials` (`34`)
  9. `signed_certificate_timestamp` (`18`)
  10. `key_share` (`51`)
  11. `supported_versions` (`43`)
  12. `signature_algorithms` (`13`)
  13. `psk_key_exchange_modes` (`45`)
  14. `record_size_limit` (`28`)
  15. `compress_certificate` (`27`)
  16. `encrypted_client_hello` (`0xfe0d`)
