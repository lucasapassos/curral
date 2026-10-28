// Package skills embeds the agent skill under skills/curral, so a running
// server can hand it to AI agents over HTTP (GET /skill/...) and nothing has
// to be installed beforehand.
package skills

import "embed"

// Curral holds skills/curral: SKILL.md, references/ and scripts/.
//
//go:embed curral/SKILL.md curral/references/*.md curral/scripts/curral.sh curral/scripts/curral.ps1 curral/scripts/install.sh
var Curral embed.FS
