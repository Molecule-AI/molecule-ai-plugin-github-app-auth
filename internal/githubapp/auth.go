// Package githubapp authenticates as a GitHub App installation and exposes
// a short-lived installation token suitable for injection as a workspace
// env var (GITHUB_TOKEN / GH_TOKEN).
//
// Auth flow per GitHub docs:
//
//	1. Mint a JWT signed with the App's RSA private key (RS256, 9-min exp).
//	2. POST the JWT to /app/installations/{installation_id}/access_tokens.
//	3. Response includes an installation token valid ~60 min + expires_at.
//	4. Cache the token in memory; refresh when <5 min remaining.
//
// The token rotates automatically across cron ticks. Every workspace in the
// platform process shares the same installation token because they all
// authenticate as the same App installation — per-agent identity is
// achieved via the App acting on their behalf, not via separate tokens.
package githubapp

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config is the operator-supplied identity for the App installation.
// All three fields are required; New returns an error on any zero value
// so misconfiguration fails loud at boot, not on the first request.
type Config struct {
	// AppID is the GitHub App's numeric ID shown at
	// https://github.com/organizations/<org>/settings/apps/<slug>.
	AppID int64

	// InstallationID identifies the specific org/user install the token
	// should authenticate as. Find it at
	// https://github.com/organizations/<org>/settings/installations/<id>.
	InstallationID int64

	// PrivateKeyPEM is the RSA private key downloaded from the App's
	// settings page, in PKCS#1 or PKCS#8 PEM form. Keep this out of
	// logs and out of version control — store as a gitignored file.
	PrivateKeyPEM []byte

	// HTTPClient is the transport used for token exchange. Optional; the
	// default client has a 30-second timeout which is plenty for a
	// single POST to api.github.com. Override for tests or to thread a
	// corporate proxy.
	HTTPClient *http.Client

	// TokenEndpoint lets tests point at httptest.Server. Defaults to
	// https://api.github.com when empty.
	TokenEndpoint string

	// RefreshBuffer is how long before expiry to mint a new token.
	// Defaults to 5 minutes — long enough to cover any one in-flight
	// workspace provision, short enough to avoid wasting the bulk of
	// each 60-minute installation-token lifetime.
	RefreshBuffer time.Duration
}

const (
	defaultTokenEndpoint = "https://api.github.com"
	defaultRefreshBuffer = 5 * time.Minute
	// jwtLifetime is how long the App JWT is valid. GitHub caps this at
	// 10 minutes; we pick 9 to leave headroom for minor clock skew
	// between our box and api.github.com.
	jwtLifetime = 9 * time.Minute
	// jwtIssuedSlack backdates `iat` by a minute so a positively-skewed
	// clock on our end (e.g. NTP not yet synced on a fresh VM) doesn't
	// produce a JWT the server rejects as "issued in the future".
	jwtIssuedSlack = 60 * time.Second
)

// Authenticator mints + caches GitHub App installation tokens.
type Authenticator struct {
	cfg        Config
	privateKey *rsa.PrivateKey

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// New parses the private key once at startup and returns an Authenticator.
// Returns an error if the config is incomplete or the key isn't parseable.
func New(cfg Config) (*Authenticator, error) {
	if cfg.AppID == 0 {
		return nil, errors.New("githubapp: AppID is required")
	}
	if cfg.InstallationID == 0 {
		return nil, errors.New("githubapp: InstallationID is required")
	}
	if len(cfg.PrivateKeyPEM) == 0 {
		return nil, errors.New("githubapp: PrivateKeyPEM is required")
	}
	key, err := parsePrivateKey(cfg.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("githubapp: parse private key: %w", err)
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.TokenEndpoint == "" {
		cfg.TokenEndpoint = defaultTokenEndpoint
	}
	if cfg.RefreshBuffer == 0 {
		cfg.RefreshBuffer = defaultRefreshBuffer
	}
	return &Authenticator{cfg: cfg, privateKey: key}, nil
}

// Token returns a cached installation token if one is still fresh, or
// mints a new one via GitHub's API. Safe for concurrent callers.
//
// The returned token string is directly usable as a bearer: both
// `Authorization: token <t>` and `GH_TOKEN=<t>` flows accept it.
//
// Concurrency: the mutex is held across the HTTP call. That serializes
// concurrent cache misses into one mint, at the cost of queuing other
// callers for the ~200-500ms the GitHub roundtrip takes. Under normal
// load that's invisible; under a stampede of N workers booting at the
// same moment, exactly one call hits GitHub and the rest instantly hit
// the post-mint cache. Alternative designs (sync.Cond, singleflight)
// would shave microseconds off the uncontended path without changing
// the worst case; not worth the added complexity here.
func (a *Authenticator) Token(ctx context.Context) (string, error) {
	tok, _, err := a.TokenWithExpiry(ctx)
	return tok, err
}

// TokenWithExpiry returns the cached installation token together with the
// time it will expire. Same caching contract as Token() — never returns an
// expired token, blocks the caller for the GitHub roundtrip on a cache
// miss. Added to support the platform's GET /admin/github-installation-token
// endpoint (molecule-core#567), where workspace credential helpers need
// both the token and a refresh-by-deadline so they can pre-warm the cache
// before next use.
func (a *Authenticator) TokenWithExpiry(ctx context.Context) (string, time.Time, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.token != "" && time.Until(a.expiresAt) > a.cfg.RefreshBuffer {
		return a.token, a.expiresAt, nil
	}

	token, expiresAt, err := a.mintInstallationToken(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	a.token = token
	a.expiresAt = expiresAt
	return token, expiresAt, nil
}

// mintInstallationToken does the actual JWT→POST exchange. Separate from
// Token() so the caching logic above is readable.
func (a *Authenticator) mintInstallationToken(ctx context.Context) (string, time.Time, error) {
	jwtStr, err := a.signAppJWT(time.Now())
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign app jwt: %w", err)
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens",
		a.cfg.TokenEndpoint, a.cfg.InstallationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(nil))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := a.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("post access_tokens: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Include the response body — GitHub's error messages are useful
		// ("integration not found", "bad installation ID", etc.) and
		// without them the 401/404 is indistinguishable from network
		// issues at the caller.
		return "", time.Time{}, fmt.Errorf(
			"access_tokens returned %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)),
		)
	}

	var payload struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", time.Time{}, fmt.Errorf("parse response: %w", err)
	}
	if payload.Token == "" {
		return "", time.Time{}, errors.New("access_tokens response missing token field")
	}
	if payload.ExpiresAt.IsZero() {
		// If GitHub ever omits expires_at, fall back to now+60m so the
		// cache still rotates. Unlikely per the spec but defensive.
		payload.ExpiresAt = time.Now().Add(60 * time.Minute)
	}
	return payload.Token, payload.ExpiresAt, nil
}

// signAppJWT produces the RS256-signed JWT that authenticates this App
// to GitHub's /app/installations endpoint.
//
// The `now` parameter lets tests pin the timestamp without touching
// system time.
func (a *Authenticator) signAppJWT(now time.Time) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    strconv.FormatInt(a.cfg.AppID, 10),
		IssuedAt:  jwt.NewNumericDate(now.Add(-jwtIssuedSlack)),
		ExpiresAt: jwt.NewNumericDate(now.Add(jwtLifetime - jwtIssuedSlack)),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return tok.SignedString(a.privateKey)
}

// parsePrivateKey accepts both PKCS#1 ("RSA PRIVATE KEY") and PKCS#8
// ("PRIVATE KEY") PEM formats. GitHub emits PKCS#1; some key rotation
// tools re-encode to PKCS#8, so accept both.
func parsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parse RSA key (tried PKCS#1 + PKCS#8): %w", err)
	}
	return key, nil
}
