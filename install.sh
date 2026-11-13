#!/usr/bin/env bash
# Compatibility wrapper for DSH's built-in plugin installer.
set -euo pipefail

VERSION="0.1.5"
PACKAGE="@lornatang/dsh-frontgate"
PROFILE="${DSH_FRONTGATE_PROFILE:-web}"

usage() {
  cat <<'EOF'
Usage: install.sh [--profile <name>]

Install or update dsh-frontgate in a DSH profile. DSH_HOME controls the
profile directory (default: ~/.dsh).
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile)
      [ "$#" -ge 2 ] && [ -n "$2" ] || die "--profile needs a value"
      PROFILE="$2"
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

case "$PROFILE" in
  ''|.|..|-*|*/*|*\\*) die "invalid profile name: $PROFILE" ;;
esac
command -v dsh >/dev/null 2>&1 || die "dsh is not in PATH"

PROFILE_DIR="${DSH_HOME:-$HOME/.dsh}/profiles/$PROFILE"

# DSH initializes its own built-in web profile when the plugin is added. A new
# custom profile needs the web template; never replace an existing directory.
if [ "$PROFILE" != "web" ] && [ ! -f "$PROFILE_DIR/package.json" ]; then
  if [ -e "$PROFILE_DIR" ] || [ -L "$PROFILE_DIR" ]; then
    die "profile directory exists without package.json: $PROFILE_DIR"
  fi
  echo "creating profile '$PROFILE' from the web template"
  dsh "$PROFILE" --from-default-profile web --help >/dev/null
  [ -f "$PROFILE_DIR/package.json" ] || die "could not create profile '$PROFILE'"
fi

if [ -f "$PROFILE_DIR/package.json" ] && grep -Fq '"dsh-frontgate"' "$PROFILE_DIR/package.json"; then
  die "legacy dsh-frontgate detected; stop DSH and follow the migration steps in README.md"
fi

echo "installing $PACKAGE@$VERSION into profile '$PROFILE'"
dsh plugin --profile "$PROFILE" add "$PACKAGE@$VERSION"

cat <<EOF

$PACKAGE@$VERSION is installed in profile '$PROFILE'.
Restart the profile, then open the gate (127.0.0.1:3090 by default).
If no password is configured or saved, its first start prints PASSWORD to stderr.
The selected profile must include the DSH web app for the gate to start.
EOF
