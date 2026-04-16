# molecule-ai-plugin-github-app-auth

GitHub App installation-token injection for Molecule AI workspaces.
Implements `provisionhook.EnvMutator` so every workspace boots with
`GITHUB_TOKEN` + `GH_TOKEN` set to a fresh, rotating installation token
instead of sharing one long-lived Personal Access Token across agents.

## Why

Without this plugin every workspace agent authenticates to GitHub as the
same shared PAT owner. All commits / PRs / issues from every role — PM,
Dev Lead, Backend Engineer, etc. — appear as the one PAT user. With this
plugin, every workspace authenticates as the **App**, and individual
roles' identity comes from commit trailers (`GIT_AUTHOR_NAME="Molecule AI
Backend Engineer"` etc., already injected by the platform).

Operationally the token rotates automatically: installation tokens are
valid for ~60 minutes, the plugin refreshes 5 minutes before expiry, no
PAT rotation ceremony.

## Prerequisites

1. A GitHub App installed on your org with permissions:
   - Contents: Write · Issues: Write · Pull requests: Write · Metadata: Read
2. The App's RSA private-key PEM file (downloaded once from the App settings).
3. The App's numeric ID and the installation ID for your org.

## Install

The plugin is a Go library. Integrate by registering its Mutator on the
platform's `WorkspaceHandler` before the HTTP server starts.

### Step 1 — Add the import + config

In `molecule-monorepo/platform/cmd/server/main.go`, after
`wh := handlers.NewWorkspaceHandler(...)`:

```go
import pluginghapp "github.com/Molecule-AI/molecule-ai-plugin-github-app-auth/cmd/server-with-github-app"

// ... after WorkspaceHandler is created ...
reg, err := pluginghapp.BuildRegistry()
if err != nil {
    log.Fatalf("github-app-auth: %v", err)
}
wh.SetEnvMutators(reg)
```

Add to `platform/go.mod`:

```
require github.com/Molecule-AI/molecule-ai-plugin-github-app-auth v0.1.0
```

Env vars (add to your `.env`):

```
GITHUB_APP_ID=3398844
GITHUB_APP_INSTALLATION_ID=124443072
GITHUB_APP_PRIVATE_KEY_FILE=/secrets/github-app.pem
```

Bind-mount the private-key file into the platform container:

```yaml
services:
  platform:
    volumes:
      - ./.secrets/github-app.pem:/secrets/github-app.pem:ro
```

### Step 2 — Rebuild + restart

```
docker compose up -d --build platform
docker ps --filter 'name=^ws-' -q | xargs docker rm -f   # liveness recreates
```

### Step 3 — Verify

```
docker exec ws-<any-id> printenv GITHUB_TOKEN
# -> ghs_...

docker exec ws-<any-id> gh auth status
# -> Logged in to github.com as app/molecule-ai[bot]
```

## What happens at runtime

1. Platform boots, reads the three env vars, parses the private key.
2. First workspace provision calls `Authenticator.Token(ctx)`:
   - Mints a JWT signed RS256 with the App private key (9-minute lifetime).
   - `POST /app/installations/{id}/access_tokens` to exchange for a ~60-min installation token.
   - Caches token + expiry.
3. Subsequent provisions within ~55 min hit the cache.
4. When <5 min remain, next call mints a fresh token.
5. `GITHUB_TOKEN` and `GH_TOKEN` are injected into every workspace's env.

## Security

- Private key never leaves the platform process — workspaces only see the short-lived installation token.
- Installation tokens expire within an hour; a compromised workspace leaks access for at most that window.
- Revoke an installation token immediately via `DELETE /installation/token` if needed.
- `.gitignore` ships with rules for `*.pem` and `.secrets/`. Don't commit the key.

## Development

```
go mod tidy
go test ./internal/... -race
```

## License

Business Source License 1.1 — © Molecule AI.
