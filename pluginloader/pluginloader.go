// Package pluginloader bridges env-var config to a registered
// provisionhook.Registry suitable for WorkspaceHandler.SetEnvMutators.
//
// Operators integrating the plugin into a custom platform binary import
// this package and call BuildRegistry() during boot:
//
//	reg, err := pluginloader.BuildRegistry()
//	if err != nil { log.Fatalf("github-app-auth: %v", err) }
//	wh.SetEnvMutators(reg)
//
// Kept in its own package (not under cmd/) so Go's main-package rule
// doesn't prevent the platform's own main from importing it.
package pluginloader

import (
	"fmt"
	"os"
	"strconv"

	"github.com/Molecule-AI/molecule-ai-plugin-github-app-auth/internal/githubapp"
	"github.com/Molecule-AI/molecule-monorepo/platform/pkg/provisionhook"
)

// BuildRegistry reads GITHUB_APP_* env vars, constructs the Authenticator,
// and returns a provisionhook.Registry with the github-app-auth Mutator
// registered.
//
// If required env vars are missing, returns nil + a clear error. Callers
// decide whether that's fatal (production — yes) or soft-skip (dev
// without the App configured — just log + continue with no mutator).
func BuildRegistry() (*provisionhook.Registry, error) {
	appID, err := strconv.ParseInt(os.Getenv("GITHUB_APP_ID"), 10, 64)
	if err != nil || appID == 0 {
		return nil, fmt.Errorf("GITHUB_APP_ID is required and must be numeric (got %q)", os.Getenv("GITHUB_APP_ID"))
	}
	installID, err := strconv.ParseInt(os.Getenv("GITHUB_APP_INSTALLATION_ID"), 10, 64)
	if err != nil || installID == 0 {
		return nil, fmt.Errorf("GITHUB_APP_INSTALLATION_ID is required and must be numeric (got %q)", os.Getenv("GITHUB_APP_INSTALLATION_ID"))
	}
	keyFile := os.Getenv("GITHUB_APP_PRIVATE_KEY_FILE")
	if keyFile == "" {
		return nil, fmt.Errorf("GITHUB_APP_PRIVATE_KEY_FILE is required (path to the App's RSA private key PEM)")
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read private key %q: %w", keyFile, err)
	}

	auth, err := githubapp.New(githubapp.Config{
		AppID:          appID,
		InstallationID: installID,
		PrivateKeyPEM:  keyPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("init github-app-auth: %w", err)
	}

	reg := provisionhook.NewRegistry()
	reg.Register(&githubapp.Mutator{Auth: auth})
	return reg, nil
}
