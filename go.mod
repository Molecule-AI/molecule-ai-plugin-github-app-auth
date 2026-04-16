module github.com/Molecule-AI/molecule-ai-plugin-github-app-auth

go 1.25.0

require github.com/golang-jwt/jwt/v5 v5.2.1

// Pin to a specific platform commit so the plugin builds against a known
// provisionhook ABI. Operators integrating the plugin into a custom binary
// set `replace` back to their local platform checkout for development.
replace github.com/Molecule-AI/molecule-monorepo/platform => ../molecule-monorepo/platform
