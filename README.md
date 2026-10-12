# Proton Calendar MCP

A Go MCP server for a single Proton account, using Proton's **undocumented internal protocol**, implemented directly in this repository. It does not execute a community CLI, require Proton Mail Bridge, or publish a calendar subscription link.

Supports local stdio, authenticated Streamable HTTP, an optional OpenAI Secure MCP Tunnel, and Dokploy. By default, all calendars accessible to your Proton account are available to the AI. Set `PROTON_CALENDAR_IDS` to restrict access to selected calendars.

## Features

Version **0.4.0** exposes 23 tools. Call `capabilities` to check the deployed version and supported operations before planning a mutation. This release expands the implementation; **it does not yet provide full Proton Calendar parity**.

| Area | Tools and behavior |
|---|---|
| Discovery | `capabilities`, `calendars_list`, `addresses_list` |
| Events | `event_list`, `event_get`, `event_create`, `event_update`, `event_delete`, `event_changes` |
| Calendar administration | `calendar_get`, `calendar_create`, `calendar_update`, `calendar_settings_update`, `calendar_delete` |
| Calendar sharing | `calendar_members`, `calendar_share`, `calendar_access_update` |
| Public ICS links | `calendar_links`, `calendar_link_create`, `calendar_link_get`, `calendar_link_delete` |
| ICS transfer | `event_export`, `events_import` |

Event creation supports optional Proton-account guests: their copies receive the shared encryption key through Proton Calendar sync. The guest list is encrypted and signed. **No invitation email is sent**; external recipients are refused before writing the event. Guest meetings you organize can be updated or deleted with explicit no-email options. Cancellation or update email delivery remains unsupported.

Delete one recurring occurrence (including a separately edited instance), the entire series, or the selected occurrence and all future occurrences. Full-series operations fetch and verify the complete series before submitting one sync batch. A failed batch may have partially applied; never automatically retry it.

Calendar creation generates encrypted calendar keys and supports HTTPS ICS subscriptions fetched by Proton. Creation requires an unrestricted calendar allowlist. Use a stable request ID: uncertain creation is blocked from replay, and a key-setup failure reports the created calendar ID for operator recovery.

Sharing a calendar grants access to its entire contents. Public links are bearer credentials: listing links omits usable URLs; retrieving or creating one explicitly returns it. A full-access public link allows Proton to decrypt the exported feed. Sharing keys are checked against Proton's published primary keys; Key Transparency and contact-pinned-key verification are not implemented.

New operations have synthetic protocol and cryptographic tests, but still need live-account validation. Existing login and event reading have been exercised by the operator. Use a dedicated test calendar when validating new write paths.

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

- Guest creation currently supports Proton recipients through Calendar sync. Invitation/update/cancellation emails, external guest creation, guest-list changes on existing events, RSVP, accepting calendar-sharing invitations, cross-calendar moves, booking pages and video conferencing remain unsupported. A request to send a cancellation notice is rejected; it is never silently treated as no-email mode.
- Recurring series can be created and read. Text/reminder edits preserve the rule and exclusions. For one deletion pass the exact `occurrence` from `event_list`, the master series ID and its current revision. Stored exceptions are deleted in the same batch as the master exclusion. `scope: "all"` deletes the entire series; `scope: "future"` with an occurrence truncates the master and removes future exceptions. Organizer guest events require `send_cancellation_notice: false`; updates require `send_update_notice: false`. Proton guests may see sync changes despite no email. Recurring rescheduling/splitting remains unsupported.
- `event_export` exports a stored event or its entire verified recurrence series, including exceptions outside the displayed date range. `events_import` creates new personal events with new UIDs. Import supports basic fields and RRULE; guests, exclusions, stored exceptions, alarms and custom VTIMEZONE components are rejected before any writes. It is not a full-fidelity backup/restore facility. Partial remote failures are reported with acknowledged results and the failing index.
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
