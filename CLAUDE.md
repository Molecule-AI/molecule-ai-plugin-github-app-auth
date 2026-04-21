# molecule-ai-plugin-github-app-auth

GitHub App installation-token injection for Molecule AI workspaces.
Implements `provisionhook.EnvMutator` so every workspace boots with
`GITHUB_TOKEN` + `GH_TOKEN` set to a fresh, rotating installation token
instead of sharing one long-lived Personal Access Token across agents.

**Version:** (from go.mod)
**Language:** Go
**Module:** `github.com/Molecule-AI/molecule-ai-plugin-github-app-auth`

---

## Why This Exists

Without this plugin, every workspace agent authenticates to GitHub as the same
shared PAT owner. All commits, PRs, and issues from every role appear as one user.

With this plugin, every workspace authenticates as the **GitHub App**, and
individual role identity comes from Git commit trailers
(`GIT_AUTHOR_NAME="Molecule AI Backend Engineer"` etc., already injected by the
platform).

Token rotation is automatic: installation tokens expire ~60 min; the plugin
refreshes 5 min before expiry.

---

## Architecture

```
github-app-auth/
├── cmd/
│   └── server-with-github-app/    # Server integration example
├── internal/
│   └── (JWT + token exchange logic)
├── pluginloader/
│   └── load.go                   # Plugin loading / registry
├── go.mod                         # Go module (1.25)
├── go.sum
└── README.md
```

The plugin implements the `EnvMutator` interface from the Molecule platform
provision hook. At workspace boot, `SetEnvMutators(reg)` registers the
`github-app-auth` mutator on the workspace handler, which injects
`GITHUB_TOKEN` and `GH_TOKEN` into every workspace container.

---

## Integration (platform binary)

### Step 1 — Register the mutator

In `platform/cmd/server/main.go`, after `WorkspaceHandler` is created:

```go
import pluginghapp "github.com/Molecule-AI/molecule-ai-plugin-github-app-auth/cmd/server-with-github-app"

reg, err := pluginghapp.BuildRegistry()
if err != nil {
    log.Fatalf("github-app-auth plugin: %v", err)
}
wh.SetEnvMutators(reg)
```

### Step 2 — Add to go.mod

```
require github.com/Molecule-AI/molecule-ai-plugin-github-app-auth v0.1.0
```

### Step 3 — Required env vars

| Variable | Description |
|---|---|
| `GITHUB_APP_ID` | Numeric GitHub App ID (from App settings page) |
| `GITHUB_APP_INSTALLATION_ID` | Installation ID for your org |
| `GITHUB_APP_PRIVATE_KEY_FILE` | Absolute path to the RSA private key PEM file |

### Step 4 — Mount the private key

Bind-mount into the platform container:

```yaml
services:
  platform:
    volumes:
      - ./.secrets/github-app.pem:/secrets/github-app.pem:ro
```

### Step 5 — Verify

```bash
docker exec ws-<id> printenv GITHUB_TOKEN
# -> ghs_...

docker exec ws-<id> gh auth status
# -> Logged in to github.com as app/molecule-ai[bot]
```

---

## Token Lifecycle

1. Platform boots → reads 3 env vars → parses private key.
2. First workspace provision → `Authenticator.Token()`:
   - Mints JWT (RS256, 9-min lifetime) signed with App private key.
   - `POST /app/installations/{id}/access_tokens` → ~60-min installation token.
   - Caches token + expiry.
3. Subsequent provisions within ~55 min → cache hit.
4. When <5 min remain → next call mints a fresh token.
5. `GITHUB_TOKEN` and `GH_TOKEN` injected into every workspace env.

---

## Security

- Private key never leaves the platform process — workspaces see only the
  short-lived installation token.
- Installation tokens expire within an hour; compromised workspace access
  window is bounded.
- To revoke immediately: `DELETE /installation/token` via the GitHub API.
- `.gitignore` ships rules for `*.pem` and `.secrets/`. **Never commit the key.**

---

## Development

```bash
go mod tidy
go test ./internal/... -race

# With local platform replace directive:
cd cmd/server-with-github-app && go build -o /tmp/test-server .
```

---

## Key Conventions

| Topic | Convention |
|---|---|
| **Go version** | 1.25 |
| **Auth method** | GitHub App JWT → installation token exchange |
| **Token TTL** | ~60 min (installation token) |
| **JWT TTL** | 9 min |
| **Refresh** | 5 min before expiry |
| **Key storage** | PEM file bind-mounted into platform container; never in image |
| **Workspaces see** | Installation token only; never the private key |
