# Security and protocol review

Reviewed references:

- [roman-16/proton-cli](https://github.com/roman-16/proton-cli/tree/a50fbe80c118800cf6c7b8a815ebdb0488c42a3f), commit `a50fbe80c118800cf6c7b8a815ebdb0488c42a3f`.
- [ProtonMail/WebClients Calendar](https://github.com/ProtonMail/WebClients/tree/1a958628797a91e40114bb50fe0d849731bc9452/applications/calendar), commit `1a958628797a91e40114bb50fe0d849731bc9452`.
- [OpenAI tunnel-client](https://github.com/openai/tunnel-client/tree/0f870e50a973fa820d4c409000059e181e8d242b), v0.0.14 commit `0f870e50a973fa820d4c409000059e181e8d242b`.

This review covers the protocol paths implemented here: SRP login, refresh, account/address key unlocking, calendar bootstrap, event cards, sync writes, bounded recurrence reads, model-event polling, credential persistence, MCP transport, and deployment. It is **not** an audit of every feature in the community CLI or Proton's monorepo, nor an independent audit of the crypto dependencies. No community CLI binary is installed or executed.

## Findings and resulting implementation

| Finding | Evidence and decision |
|---|---|
| Calendar data is split into signed/encrypted parts with different property ownership. | WebClients `packages/shared/lib/calendar/constants.ts`, `veventHelper.ts`, `serialize.ts`, `formatData.ts`; CLI `internal/ical/vevent.go`, `internal/crypto/pgp/cards.go`. Follow Proton's card types and separate key packets. |
| CLI serializes `STATUS` in shared encrypted content, differing from the current official field lists. | `VEvent.SharedEncrypted()` versus `CALENDAR_SIGNED_FIELDS`. Put initial `STATUS:CONFIRMED` in `CalendarEventContent`, preserve existing calendar-specific cards by omission during shared edits. |
| Cryptographic reads do not automatically imply a verified signature. | CLI's card helpers report separate verdicts. Unknown/unsigned card types are refused here; unverifiable signed content is marked explicitly and cannot be rewritten/deleted. |
| Address keys can be token-protected under user keys. | CLI `internal/account/keys/keys.go`. Decrypt and verify migrated address tokens, then unlock the address key; never treat a token as plaintext. |
| Primary keys and historical decryption keys have different roles. | CLI `calendar.go` and account `Rings`. Encrypt/sign with primary keys; retain historical active keys for reading. Missing primary keys block writes. |
| A successful HTTP status is insufficient for sync success. | Official sync API and CLI `sync.go`. Require exactly one response entry, the matching index, success code, and expected event identity for create/update. |
| Failed network writes cannot safely be blindly retried. | CLI client distinguishes repeatable requests. This implementation never retries ambiguous writes; create intent is saved before submission and success after acknowledgement. |
| Refresh tokens rotate and cannot safely be used concurrently. | CLI client/session code. Serialize calls, use an exclusive vault lock, persist rotated credentials before retry, and block further calls if persistence fails. |
| Date-window subtraction is not an event-deletion signal. | CLI index and official model-event endpoints. Use the native event feed; expose pagination and upstream history reset explicitly. |
| Editing a parsed subset can silently drop data. | CLI event model intentionally preserves recurrence. Here updates edit original shared card components, preserving unknown properties, recurrence/exclusion fields, personal parts, colors, and omitted reminders. Unsupported layouts fail before mutation. |
| Public listeners and private network listeners are separate trust boundaries. | Neighboring MCP deployments and tunnel configuration. Both listeners require distinct bearer tokens; the tunnel injects its own private-hop credential. Host validation and cross-origin protection apply before MCP. |

## Security controls

- Fixed Proton HTTPS endpoint, TLS validation enabled, redirects disabled, bounded response bodies, sanitized API errors. No arbitrary URL/API/shell/file-access tools.
- Constant-time comparison of hashed HTTP bearer tokens, exact Host allowlist, cross-origin protection, bounded request bodies/headers and timeouts. Use proxy rate limits for internet-facing deployment.
- Optional calendar allowlist enforced for every event operation and feed call when configured; empty/unset allows all account calendars. Exact identifier validation prevents path injection.
- AES-256-GCM vault with authenticated format header, independent random nonces, mode-600 atomic writes, fsync, and a single-process filesystem lock. Separate encryption-key storage. No original account password persisted.
- Password input only through a local terminal; SRP checks Proton's signed modulus through the official library and checks the server proof before accepting a session. TOTP and separate mailbox-password support; no 2FA/HV bypass.
- Native event encryption through official gopenpgp ProtonV1 profile. Calendar passphrase and address token verification, primary write keys, existing event session-key reuse, and clearing private key parameters on operation exit.
- No calendar bodies in application logs or on disk. The vault's operation ledger stores only create identity/fingerprint metadata and credentials. Returned event text is explicitly treated as untrusted.
- Containers run as UID 10001, read-only root filesystems, bounded tmpfs, dropped capabilities, no-new-privileges, and bounded processes/memory. No published private tunnel port.

## Remaining risks and validation limits

Validation performed: `go test -race ./...`, `go vet ./...`, Docker image builds, Compose configuration checks, and container executable smoke checks. Synthetic SRP tests verify the mutual proof exchange, TOTP, refusal of unsigned moduli, and refusal of a forged server proof. Encrypted event fixtures cover native create/read/edit/delete, create replay/uncertain outcomes, revisions, signature tampering, and change-feed reset/deletion behavior. Recurrence fixtures cover exclusions, overrides, and Kyiv DST.

Go vulnerability scanning reported **zero reachable vulnerabilities and zero vulnerabilities in imported packages**. It reported module-level advisory `GO-2026-5932` for the unused `golang.org/x/crypto/openpgp` package; this server imports Proton's maintained `github.com/ProtonMail/go-crypto/openpgp` through go-srp/gopenpgp, rather than the advisory's package. This is a point-in-time scan, not a guarantee about future advisories.

Proton can change its internal API without notice. Synthetic fixture tests establish internal consistency with inspected source; they do not establish acceptance by Proton's live service. Use a dedicated calendar for the first live round trip, check it in Proton's own UI, and keep advanced invitation/occurrence writes disabled until their protocol is implemented and validated.

This is a single-account service: an MCP bearer grants access to every account calendar by default, or only the configured calendars when an allowlist is set. It does not implement multi-user OAuth or Key Transparency. The server holds decryption capability while running, and an AI host receives plaintext events returned by tools. Read-only filesystem controls do not protect against a compromised process holding the vault key.

Revision checks cannot make the upstream write atomic with a preceding read. Credentials are excluded from errors, but both vault and encryption key must be protected and backed up. Login session revocation, hardware-key-only sign-in, CAPTCHA flows, recurring write transactions, invitation delivery, and automatic notification scheduling are not provided by this release.
