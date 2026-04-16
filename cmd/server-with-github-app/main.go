// Command server-with-github-app is a boot-time config validator for the
// github-app-auth plugin.
//
// It reads GITHUB_APP_* env vars, parses the private key, and prints the
// integration snippet operators should paste into their platform's
// cmd/server/main.go. It does NOT replace the platform — the plugin
// integrates as a library (see pluginloader.BuildRegistry).
//
// Run this to fail-fast on a misconfigured deploy:
//
//	GITHUB_APP_ID=…  GITHUB_APP_INSTALLATION_ID=…  GITHUB_APP_PRIVATE_KEY_FILE=…  \
//	    go run ./cmd/server-with-github-app
//
// Exit 0 with the integration snippet if config is valid; exit 1 with a
// specific error otherwise.
package main

import (
	"fmt"
	"log"

	"github.com/Molecule-AI/molecule-ai-plugin-github-app-auth/pluginloader"
)

func main() {
	reg, err := pluginloader.BuildRegistry()
	if err != nil {
		log.Fatalf("github-app-auth: %v", err)
	}
	fmt.Printf("github-app-auth: registry ready with %d mutator(s) — config OK\n", reg.Len())
	fmt.Println()
	fmt.Println("Integration: in platform/cmd/server/main.go, after wh := handlers.NewWorkspaceHandler(...),")
	fmt.Println("add:")
	fmt.Println()
	fmt.Println(`    import pluginloader "github.com/Molecule-AI/molecule-ai-plugin-github-app-auth/pluginloader"`)
	fmt.Println()
	fmt.Println(`    reg, err := pluginloader.BuildRegistry()`)
	fmt.Println(`    if err != nil { log.Fatalf("github-app-auth: %v", err) }`)
	fmt.Println(`    wh.SetEnvMutators(reg)`)
	fmt.Println()
	fmt.Println("then rebuild the platform image.")
}
