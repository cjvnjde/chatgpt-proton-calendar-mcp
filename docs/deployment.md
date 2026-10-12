# Deployment

The base `docker-compose.yml` runs one native MCP process with an encrypted named volume and no tunnel. Port 8080 requires a bearer token. The optional tunnel override adds port 8081 with a **different** bearer token and a pinned official tunnel client. Neither port is published by base Compose.

## Docker initialization

```sh
cp .env.example .env
chmod 600 .env
```

Fill `PROTON_VAULT_KEY` and `MCP_BEARER_TOKEN` with independently generated `openssl rand -hex 32` values. Keep the vault key backed up separately. Leave `PROTON_CALENDAR_IDS` empty for access to all account calendars, including calendars added later. Optionally use discovery to restrict access to selected IDs.

```sh
docker compose build
docker compose run --rm --no-deps proton-calendar-mcp login --username you@proton.me
docker compose run --rm --no-deps proton-calendar-mcp calendars
```

The login command requires an interactive terminal. Optionally set `PROTON_CALENDAR_IDS` to chosen IDs, comma-separated; leave it empty for all calendars. Then start:

```sh
docker compose up -d
```

For loopback access on the Docker host:

```sh
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d
```

Connect an HTTP MCP client to `http://127.0.0.1:8080/mcp` with `Authorization: Bearer <MCP_BEARER_TOKEN>`. Plain HTTP is intended only for loopback/private networking; public access uses a TLS reverse proxy.

## Dokploy

The service uses explicit `${VAR}` environment references and a named volume, matching [Dokploy's Compose guidance](https://docs.dokploy.com/docs/core/docker-compose). Configure the domain through its [Compose Domains UI](https://docs.dokploy.com/docs/core/docker-compose/domains); domain changes require redeployment.

1. Create a Docker Compose application using this repository and `docker-compose.yml`.
2. Set Environment values from `.env.example`, with independent vault and bearer secrets. Choose `PROTON_TIMEZONE`, and add your exact public domain to `MCP_ALLOWED_HOSTS` alongside the internal/health hosts already shown. Host values omit the scheme and include a port when the incoming request includes one.
3. Deploy normally. The HTTP container stays running and healthy before Proton login. Authenticated MCP requests return HTTP 503 until a session is available; the tunnel may retry while setup is pending.
4. Open the **proton-calendar-mcp container terminal** in Dokploy, select `/bin/sh`, and run:

   ```sh
   proton-calendar-mcp login --username you@proton.me
   ```

   Enter the password and any requested TOTP/mailbox password at the hidden prompts. The server automatically loads the saved session within about a second after login exits. No stop or redeploy is needed. From a server SSH terminal, the equivalent command is `docker compose ... exec proton-calendar-mcp proton-calendar-mcp login --username you@proton.me`, using the same project, environment, and Compose files as Dokploy.
5. Leave `PROTON_CALENDAR_IDS` empty for all calendars, or put selected IDs into Environment, then redeploy. Attach the HTTPS domain to service `proton-calendar-mcp`, **container port 8080**, path `/mcp`. Require HTTPS and rate-limit requests at the proxy. Do not route port 8081 publicly.
6. Add the HTTPS `/mcp` URL to a client that supports bearer authentication. There is no OAuth authorization server in this project.

Do not put the Proton account password or TOTP seed in Dokploy Environment. They are needed only during interactive login. `PROTON_VAULT_KEY` and MCP tokens are long-lived secrets; Dokploy/Docker administrators can inspect environment credentials. Where your platform supports secret-file mounts, local binaries also accept `PROTON_VAULT_KEY_FILE`, `MCP_BEARER_TOKEN_FILE`, and `MCP_TUNNEL_TOKEN_FILE`; restrict these to mode 600 and the process owner. The shipped Compose file uses Environment secrets for compatibility with the neighboring projects.

After a session has been activated, stop the service before replacing it so its vault lock is released. Run login with the same key, named volume, and Compose project, then restart. Refresh tokens are persisted immediately after successful rotation. Run one instance; replicas or separate copies of the same session can invalidate each other's refresh tokens.

## Optional OpenAI Secure MCP Tunnel

The official [Secure MCP Tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) explains tunnel provisioning and workspace association. The tunnel uses outbound HTTPS to OpenAI and private access to the server.

Set `CONTROL_PLANE_API_KEY`, `CONTROL_PLANE_TUNNEL_ID`, and a new independent `MCP_TUNNEL_TOKEN`, then:

```sh
docker compose -f docker-compose.yml -f docker-compose.tunnel.yml up -d --build
```

For Dokploy, configure both Compose files if supported, or merge the optional service/environment into its Compose editor. Target the tunnel at `http://proton-calendar-mcp:8081/mcp`. The override uses `MCP_EXTRA_HEADERS` and discovery headers backed by `MCP_TUNNEL_AUTHORIZATION` to authenticate the private hop. These settings were checked against tunnel-client v0.0.14 source and configuration docs; they require that pinned version or a compatible later release.

Choose the provisioned tunnel in the OpenAI host. Keep port 8081 private. The external HTTP endpoint can remain available concurrently or have no public route.

## Storage and backups

The volume contains `vault.enc` and a lock file. The vault encrypts session tokens, the derived mailbox passphrase, account identity, and the bounded create-operation ledger with AES-256-GCM. Event bodies are fetched/decrypted in memory rather than stored locally.

Back up the vault and its encryption key separately. Possession of both allows impersonation and decryption; the key passphrase is a sensitive credential even though it is not the original account password. Replacing the environment key does **not** rotate an existing vault—it makes it unreadable. Never discard the operation ledger while an uncertain create remains unresolved.

`docker compose down -v` deletes the vault. Updating the image preserves it when the Compose application/project identity stays the same. Revoke the account session through Proton's UI when retiring a deployment; rotate both MCP tokens independently if they are exposed.

## Troubleshooting

| Symptom | Action |
|---|---|
| `vault is already in use` | Stop the server before running operator commands. |
| HTTP 503: Proton login required | Run `proton-calendar-mcp login --username you@proton.me` in the running container terminal. |
| HTTP 401 | Check the MCP bearer token for that listener; it is separate from Proton credentials. |
| HTTP 421 | Add the exact incoming Host, including its port, to `MCP_ALLOWED_HOSTS`. |
| Proton 401 from a tool | Session refresh failed or was revoked; stop and log in again. |
| Human verification required | Complete verification using Proton's supported UI; no CAPTCHA bypass exists. |
| Signature failure on mutation | Use Proton's UI; do not disable verification to force the edit. |
| Previous create outcome unknown | Reconcile the signed UID in the error against current events before another create. |

`/healthz` checks process liveness, not login readiness, account validity, or upstream connectivity. It remains healthy while waiting for first login. It deliberately returns no credentials or calendar details.
