// Package version carries build identification.
package version

// Version is the release version, overridden at build time with
// -ldflags "-X github.com/linktoming/ai-auth/internal/version.Version=..."
var Version = "0.1.0-dev"

// Commit is the source revision, set the same way.
var Commit = "unknown"
