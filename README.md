# Proton Calendar MCP

A Go MCP server for a single Proton account, using Proton's **undocumented internal protocol**, implemented directly in this repository. It does not execute a community CLI, require Proton Mail Bridge, or publish a calendar subscription link.

Supports local stdio, authenticated Streamable HTTP, an optional OpenAI Secure MCP Tunnel, and Dokploy. By default, all calendars accessible to your Proton account are available to the AI. Set `PROTON_CALENDAR_IDS` to restrict access to selected calendars.

## Features

| Tool | Behavior |
|---|---|
| `calendars_list` | Discover accessible calendars and write permissions. |
| `event_list` | Date-range lookup, text search, pagination, all-day events, and recurring occurrences with exclusions and stored overrides. |
| `event_get` | Read a stored event and its revision/signature status. |
| `event_create` | Create encrypted personal events, optional daily/weekly/monthly/yearly recurrence, and display reminders. Stable request IDs prevent duplicate submissions. |
| `event_update` | Partial text, time, and reminder edits with a revision check. Preserve omitted properties and the existing encryption session key. |
| `event_delete` | Delete verified personal events or individual normal recurring occurrences with a revision check. |
| `event_changes` | Poll Proton's native created/updated/deleted event feed using a caller-owned cursor. |

This is a first implementation, not a Proton-supported integration. No live account has been used to validate it yet. Synthetic tests exercise the native protocol and cryptographic round trips; use a dedicated test calendar before granting access to production calendars.

## Local setup

Requires Linux and Go 1.27.1 or newer. The vault uses a Linux filesystem lock so two processes cannot spend the same refresh token concurrently.

```sh
make build
./bin/proton-calendar-mcp init
./bin/proton-calendar-mcp login --username you@proton.me
./bin/proton-calendar-mcp calendars
```

Login prompts for the account password and, if needed, a TOTP code and separate mailbox password. It verifies the SRP server proof, unlocks the account/address keys, and saves only session tokens and the **derived key passphrase** in the encrypted vault. No AI tool accepts passwords or tokens. When Proton requests CAPTCHA verification, the terminal prints a `https://verify.proton.me/` link. Open it in your browser, solve the challenge yourself, then press Enter in the terminal to continue. TOTP is requested separately. Hardware-key-only authentication and non-CAPTCHA human verification methods are not implemented.

Legacy unsalted account keys are refused because supporting them would require persisting the original mailbox/account password instead of a derived passphrase.

Configure your MCP client below. Leave `PROTON_CALENDAR_IDS` empty for all calendars, or optionally choose exact IDs from `calendars` to restrict access:

```json
{
  "mcpServers": {
    "proton-calendar": {
      "command": "/absolute/path/bin/proton-calendar-mcp",
      "args": ["serve"],
      "env": {
        "MCP_TRANSPORT": "stdio",
        "PROTON_VAULT_PATH": "/absolute/path/data/vault.enc",
        "PROTON_VAULT_KEY_FILE": "/absolute/path/secrets/vault.key",
        "PROTON_CALENDAR_IDS": "",
        "PROTON_TIMEZONE": "Europe/Kyiv"
      }
    }
  }
}
```

HTTP deployments start healthy before first login. Run `proton-calendar-mcp login --username you@proton.me` in the running container terminal; the server automatically activates the saved session. Once active, one process owns the vault: stop the MCP server before rerunning `login` or `calendars`. Do not run multiple client-launched stdio processes against one vault; use HTTP to share one server process.

## Deployment

See [deployment](docs/deployment.md) for Docker, direct HTTPS, optional tunnel, and Dokploy setup. Base Compose runs only the MCP server; tunnel credentials and the tunnel binary are unnecessary without the tunnel override.

## Monitoring

Call `event_changes` with a calendar ID and no cursor to start from now. Save its returned cursor outside the conversation if monitoring must survive a new chat. Pass that cursor on subsequent calls; drain `has_more` pages before waiting at least one minute between polls. On `refresh_required`, history is incomplete: obtain a new baseline **before** relisting the relevant events, then continue from it so changes during the relisting are not lost.

Monitoring is pull-based. The MCP server does not wake an inactive AI, create a schedule, or send email/Slack/push alerts. Your MCP host or an explicitly configured automation must invoke it periodically. Deletions return the stored event ID; retain your own previous event list if you need the deleted title.

## Current boundaries

- Writes target personal events without attendees or an organizer. Invitation handling, participant emails, sharing, booking pages, calendar administration, and cross-calendar moves are not exposed.
- Recurring series can be created and read. Text/reminder edits preserve the existing rule and exclusions. Delete a normal recurring occurrence by passing its exact `occurrence` from `event_list`, the series ID, and a fresh revision from `event_get`. This adds an EXDATE and preserves other dates. Reread the revision between deletions. Whole-series deletion, deletion of separately edited occurrences, rescheduling, and splitting a series remain unsupported.
- Date queries use an inclusive start and exclusive end, with at most 90 days per query. All-day end dates are exclusive. Provide RFC3339 timestamps with explicit offsets and an IANA timezone for timed recurring events.
- IANA timezones are supported, with a bundled timezone database for legacy aliases such as `Europe/Kiev`; arbitrary custom VTIMEZONE definitions and `RANGE` overrides are refused. Dense subdaily rules and subdaily selectors are refused. Expansion and upstream pagination limits produce an error rather than a silently incomplete schedule.
- Signatures are checked against this account's address keys. Events signed by other people can be read with `verified: false`; they cannot be edited/deleted. This is cryptographic verification against fetched account keys, not a Key Transparency implementation.
- Revision checks detect changes between the last read and the fresh pre-write read. Proton's sync API offers no verified `If-Match` contract here; another client can still race after that check.
- After an uncertain create, the persisted request ID blocks another submission. The error supplies the signed UID for reconciliation with `event_list`; use Proton's UI if necessary. Updates/deletes are never automatically resent after a network failure.

See [tool examples](docs/tools.md), [security and source review](docs/security-review.md), and [third-party notices](THIRD_PARTY_NOTICES.md).

## Development

```sh
make check
```

Tests use synthetic keys and a local mock API, never an account from your environment. CI also builds the main Docker image. Keep `go.sum` committed and review protocol changes against the pinned source references before upgrading.
