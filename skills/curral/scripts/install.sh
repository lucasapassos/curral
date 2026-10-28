#!/bin/sh
# Installs the curral agent skill: SKILL.md, references/ and scripts/.
#
#   sh install.sh [DIR]      DIR defaults to ./curral
#
# The files come from CURRAL_SKILL_SOURCE, a base URL that serves them at
# SKILL.md, references/api.md and scripts/*. By default that is this skill's
# directory in the curral repository on GitHub, at the ref in CURRAL_SKILL_REF
# (default main; use the server's version, e.g. v0.8.0, to match it). A curral
# server started with --serve-skill all serves this script with its own URL
# as the source. Nothing else is written: credentials are set up afterwards
# by the user, with DIR/scripts/curral.sh login.
set -eu
ref=${CURRAL_SKILL_REF:-main}
src=${CURRAL_SKILL_SOURCE:-https://raw.githubusercontent.com/lucasapassos/curral/$ref/skills/curral}
src=${src%/}
dir=${1:-./curral}
mkdir -p "$dir/references" "$dir/scripts"
for f in SKILL.md references/api.md scripts/curral.sh scripts/curral.ps1 scripts/install.sh; do
	curl -fsSL "$src/$f" -o "$dir/$f"
done
chmod +x "$dir/scripts/curral.sh" "$dir/scripts/install.sh"
echo "curral: skill installed in $dir (from $src)" >&2
echo "curral: read $dir/SKILL.md; the user sets up credentials with: $dir/scripts/curral.sh login" >&2
