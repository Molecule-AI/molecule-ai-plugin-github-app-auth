package githubapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// --- Test helpers ----------------------------------------------------------

// testKey generates a fresh RSA key and returns its PKCS#1 PEM.
// Regenerating per-test is cheap (~100ms) and keeps tests hermetic.
func testKey(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// testServer returns an httptest.Server that responds to
// /app/installations/:id/access_tokens with the given status + body.
// bodyFn receives the JWT the client sent so tests can assert on it.
func testServer(t *testing.T, status int, responseBody string, onReq func(*http.Request)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if onReq != nil {
			onReq(r)
		}
		w.WriteHeader(status)
		w.Write([]byte(responseBody))
	}))
}

// --- Config validation -----------------------------------------------------

func TestNew_RejectsZeroAppID(t *testing.T) {
	_, err := New(Config{InstallationID: 1, PrivateKeyPEM: testKey(t)})
	if err == nil || !strings.Contains(err.Error(), "AppID is required") {
		t.Errorf("expected AppID error, got %v", err)
	}
}

func TestNew_RejectsZeroInstallationID(t *testing.T) {
	_, err := New(Config{AppID: 1, PrivateKeyPEM: testKey(t)})
	if err == nil || !strings.Contains(err.Error(), "InstallationID is required") {
		t.Errorf("expected InstallationID error, got %v", err)
	}
}

func TestNew_RejectsEmptyPrivateKey(t *testing.T) {
	_, err := New(Config{AppID: 1, InstallationID: 1})
	if err == nil || !strings.Contains(err.Error(), "PrivateKeyPEM is required") {
		t.Errorf("expected PrivateKeyPEM error, got %v", err)
	}
}

func TestNew_RejectsMalformedPEM(t *testing.T) {
	_, err := New(Config{AppID: 1, InstallationID: 1, PrivateKeyPEM: []byte("not-pem")})
	if err == nil || !strings.Contains(err.Error(), "parse private key") {
		t.Errorf("expected parse error, got %v", err)
	}
}

// --- JWT claim structure ---------------------------------------------------

func TestSignAppJWT_ClaimStructure(t *testing.T) {
	keyPEM := testKey(t)
	a, err := New(Config{AppID: 3398844, InstallationID: 1, PrivateKeyPEM: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tokStr, err := a.signAppJWT(now)
	if err != nil {
		t.Fatal(err)
	}

	// Parse + verify with the corresponding public key — this is exactly
	// what GitHub does server-side, so a passing test here means the JWT
	// shape is wire-compatible.
	parsed, err := jwt.Parse(tokStr, func(t *jwt.Token) (interface{}, error) {
		return &a.privateKey.PublicKey, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("parse+verify: err=%v valid=%v", err, parsed != nil && parsed.Valid)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims wrong type: %T", parsed.Claims)
	}

	if iss := claims["iss"]; iss != "3398844" {
		t.Errorf("iss: got %v want 3398844", iss)
	}

	// iat should be ~60s before `now` (the jwtIssuedSlack backdate).
	iat := int64(claims["iat"].(float64))
	if diff := now.Unix() - iat; diff < 55 || diff > 65 {
		t.Errorf("iat offset from now: got %ds, want ~60s (jwtIssuedSlack)", diff)
	}

	// exp should be ~9m-60s ahead of now (9m jwtLifetime minus the 60s slack).
	exp := int64(claims["exp"].(float64))
	if diff := exp - now.Unix(); diff < 475 || diff > 485 {
		t.Errorf("exp offset from now: got %ds, want ~480s (9m - 60s slack)", diff)
	}

	// Algorithm must be RS256 per GitHub spec. HS256 would be accepted by
	// jwt.Parse if it used the secret as HMAC — explicit check locks it.
	if alg := parsed.Header["alg"]; alg != "RS256" {
		t.Errorf("alg: got %v want RS256", alg)
	}
}

// --- Cache behaviour -------------------------------------------------------

func TestToken_CacheHitAvoidsRefresh(t *testing.T) {
	var calls int32
	srv := testServer(t, 201, `{"token":"ghs_cached","expires_at":"2099-01-01T00:00:00Z"}`, func(*http.Request) {
		atomic.AddInt32(&calls, 1)
	})
	defer srv.Close()

	a, err := New(Config{AppID: 1, InstallationID: 1, PrivateKeyPEM: testKey(t), TokenEndpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}

	// Two back-to-back calls — second must hit cache.
	for i := 0; i < 2; i++ {
		tok, err := a.Token(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if tok != "ghs_cached" {
			t.Errorf("token: got %q", tok)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("HTTP calls: got %d want 1 (second call should hit cache)", got)
	}
}

func TestToken_NearExpiryRefreshes(t *testing.T) {
	var calls int32
	// Token that expires in 1 minute — which is inside the default
	// 5-minute refresh buffer, so the cache MISS even on first-ever
	// store would re-fetch on the next call.
	srv := testServer(t, 201, fmt.Sprintf(
		`{"token":"ghs_near_expiry","expires_at":%q}`,
		time.Now().Add(1*time.Minute).UTC().Format(time.RFC3339),
	), func(*http.Request) {
		atomic.AddInt32(&calls, 1)
	})
	defer srv.Close()

	a, err := New(Config{AppID: 1, InstallationID: 1, PrivateKeyPEM: testKey(t), TokenEndpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}

	// First call populates the cache; second call sees <5min remaining
	// and refreshes.
	a.Token(context.Background())
	a.Token(context.Background())

	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("HTTP calls: got %d want 2 (near-expiry should trigger refresh)", got)
	}
}

func TestToken_ConcurrentCallsDontDuplicateRefresh(t *testing.T) {
	var calls int32
	srv := testServer(t, 201, `{"token":"ghs_concurrent","expires_at":"2099-01-01T00:00:00Z"}`, func(*http.Request) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(20 * time.Millisecond) // simulate slow github
	})
	defer srv.Close()

	a, err := New(Config{AppID: 1, InstallationID: 1, PrivateKeyPEM: testKey(t), TokenEndpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.Token(context.Background())
		}()
	}
	wg.Wait()

	// At least one call must happen; we tolerate up to 2 because the
	// double-check inside Token() prevents a perfectly synchronised
	// stampede but the test timing is unpredictable. More than 2 means
	// the double-check logic is broken.
	got := atomic.LoadInt32(&calls)
	if got < 1 || got > 2 {
		t.Errorf("HTTP calls under concurrency: got %d want 1-2", got)
	}
}

// --- Error surfacing -------------------------------------------------------

func TestToken_404_IncludesResponseBody(t *testing.T) {
	srv := testServer(t, 404,
		`{"message":"Integration not found","documentation_url":"..."}`,
		nil,
	)
	defer srv.Close()

	a, err := New(Config{AppID: 1, InstallationID: 999, PrivateKeyPEM: testKey(t), TokenEndpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Token(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "404") || !strings.Contains(err.Error(), "Integration not found") {
		t.Errorf("error should include status + body: %v", err)
	}
}

func TestToken_RequestIncludesBearer(t *testing.T) {
	var gotAuth string
	srv := testServer(t, 201, `{"token":"x","expires_at":"2099-01-01T00:00:00Z"}`, func(r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
	})
	defer srv.Close()

	a, err := New(Config{AppID: 1, InstallationID: 1, PrivateKeyPEM: testKey(t), TokenEndpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	a.Token(context.Background())

	if !strings.HasPrefix(gotAuth, "Bearer ey") {
		t.Errorf("Authorization header: got %q, want 'Bearer <jwt>'", gotAuth)
	}
}

// --- Mutator interface -----------------------------------------------------

func TestMutator_NameIsStable(t *testing.T) {
	m := &Mutator{}
	if m.Name() != "github-app-auth" {
		t.Errorf("name: got %q", m.Name())
	}
}

func TestMutator_InjectsBothEnvNames(t *testing.T) {
	srv := testServer(t, 201, `{"token":"ghs_injected","expires_at":"2099-01-01T00:00:00Z"}`, nil)
	defer srv.Close()

	a, err := New(Config{AppID: 1, InstallationID: 1, PrivateKeyPEM: testKey(t), TokenEndpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	m := &Mutator{Auth: a}

	env := map[string]string{}
	if err := m.MutateEnv(context.Background(), "ws-test", env); err != nil {
		t.Fatal(err)
	}
	if env["GITHUB_TOKEN"] != "ghs_injected" {
		t.Errorf("GITHUB_TOKEN: got %q", env["GITHUB_TOKEN"])
	}
	if env["GH_TOKEN"] != "ghs_injected" {
		t.Errorf("GH_TOKEN: got %q", env["GH_TOKEN"])
	}
}

func TestMutator_PropagatesAuthError(t *testing.T) {
	srv := testServer(t, 401, `{"message":"Bad credentials"}`, nil)
	defer srv.Close()

	a, err := New(Config{AppID: 1, InstallationID: 1, PrivateKeyPEM: testKey(t), TokenEndpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	m := &Mutator{Auth: a}

	env := map[string]string{}
	err = m.MutateEnv(context.Background(), "ws-test", env)
	if err == nil {
		t.Fatal("expected error from auth failure")
	}
	if !strings.Contains(err.Error(), "github-app-auth") {
		t.Errorf("error should be prefixed with mutator name: %v", err)
	}
	if _, ok := env["GITHUB_TOKEN"]; ok {
		t.Errorf("env should NOT be mutated on error, but GITHUB_TOKEN was set")
	}
}

func TestMutator_NilAuthReturnsError(t *testing.T) {
	m := &Mutator{Auth: nil}
	err := m.MutateEnv(context.Background(), "ws", map[string]string{})
	if err == nil || !strings.Contains(err.Error(), "Authenticator is nil") {
		t.Errorf("expected nil-auth error, got %v", err)
	}
}

func TestMutator_NilEnvReturnsError(t *testing.T) {
	m := &Mutator{Auth: &Authenticator{}}
	err := m.MutateEnv(context.Background(), "ws", nil)
	if err == nil || !strings.Contains(err.Error(), "env map is nil") {
		t.Errorf("expected nil-env error, got %v", err)
	}
}
