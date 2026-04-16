// Mutator adapts the Authenticator to the platform's provisionhook.EnvMutator
// interface so it can be registered via WorkspaceHandler.SetEnvMutators and
// inject GITHUB_TOKEN / GH_TOKEN at workspace boot.
package githubapp

import (
	"context"
	"fmt"
)

// Mutator implements provisionhook.EnvMutator. Registered once at platform
// boot; every workspace provision calls MutateEnv to receive a fresh
// installation token (or a cached one if still within the refresh buffer).
type Mutator struct {
	Auth *Authenticator
}

// Name satisfies provisionhook.EnvMutator. The value is surfaced in error
// messages if this mutator fails, so operators debugging a provision
// failure can distinguish it from other plugins in the chain.
func (m *Mutator) Name() string { return "github-app-auth" }

// MutateEnv injects GITHUB_TOKEN and GH_TOKEN (the two conventional names
// gh/octokit/go-github recognise) into the workspace's env map.
//
// Workspace ID is logged but not used — every workspace under the same
// installation shares the same token, because per-agent identity is
// achieved via the App's OAuth identity, not per-workspace distinct tokens.
func (m *Mutator) MutateEnv(ctx context.Context, workspaceID string, env map[string]string) error {
	if m.Auth == nil {
		return fmt.Errorf("github-app-auth: Authenticator is nil")
	}
	if env == nil {
		return fmt.Errorf("github-app-auth: env map is nil")
	}
	token, err := m.Auth.Token(ctx)
	if err != nil {
		return fmt.Errorf("github-app-auth: %w", err)
	}
	// Both names set. gh and actions/checkout prefer GH_TOKEN; octokit
	// and most Go SDKs read GITHUB_TOKEN. Setting both avoids making
	// workspace prompts care which convention wins.
	env["GITHUB_TOKEN"] = token
	env["GH_TOKEN"] = token
	return nil
}
