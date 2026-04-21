# Known Issues

Active and recently resolved issues for `github-app-auth`.

---

## Active Issues

*(None currently open. File an issue if you encounter a problem.)*

---

## Known Gotchas

### Private key file must be present before platform starts

**Severity:** Medium
**Impact:** If `GITHUB_APP_PRIVATE_KEY_FILE` points to a non-existent path, the
platform will crash at startup (or at first workspace provision, depending on
timing).

**Workaround:** Verify the file exists and is readable before starting the
platform:

```bash
test -r /secrets/github-app.pem && echo "key OK" || echo "key MISSING"
```

---

### App installation must have correct permissions

**Severity:** Medium
**Detail:** If the GitHub App is installed without the right permissions
(Contents: Write, Issues: Write, PRs: Write, Metadata: Read), `gh` commands
inside workspaces will fail with `GraphQL` errors even though `gh auth status`
reports logged in.

**Workaround:** After installing the App, verify each scope:

```bash
gh auth status  # basic login OK
gh api user      # verify metadata access
gh api repos --owner @me  # verify repository listing
```

---

### `replace` directive in go.mod breaks `go get`

**Severity:** Low
**Detail:** The `replace` directive in `go.mod` points to a local platform
checkout (`../molecule-monorepo/platform`). This is correct for local
development but breaks CI/CD pipelines that clone a single repo.

**Workaround:** CI should override the replace directive:

```bash
go mod edit -dropreplace github.com/Molecule-AI/molecule-monorepo/platform
go mod tidy
go build ./...
```

Or use a `replace` in a `go.work` file for local development only.

---

### Installation token is org-scoped, not repo-scoped

**Severity:** Low
**Detail:** The installation token grants access to all repos the App is installed on. Workspaces cannot be isolated to a single repo via this plugin alone.

**Workaround:** For per-repo token isolation, combine with a second token
injection step that uses repo-scoped PATs, or use the App's repository
fine-grained access tokens (beta) if available.

---

## Recently Resolved

*(None yet.)*
