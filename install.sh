#!/usr/bin/env bash
# Install dsh-frontgate into a DeepSeek Harness profile.
set -euo pipefail

VERSION="v0.1.0"
REPO="Lornatang/dsh-frontgate"
PROFILE="${DSH_FRONTGATE_PROFILE:-web}"

usage() {
  cat <<'EOF'
Usage: install.sh [--profile <name>]

Installs dsh-frontgate into a DeepSeek Harness profile.
Environment: DSH_HOME sets the harness home directory (default: ~/.dsh).
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile)
      PROFILE="${2:-}"
      [ -n "$PROFILE" ] || { echo "error: --profile needs a value" >&2; exit 2; }
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

die() {
  echo "error: $*" >&2
  exit 1
}

command -v dsh >/dev/null 2>&1 || die "dsh is not in PATH"
command -v node >/dev/null 2>&1 || die "node is not in PATH"

export DSH_HOME="${DSH_HOME:-$HOME/.dsh}"
PROFILE_DIR="$DSH_HOME/profiles/$PROFILE"
NODE_VERSION="$(node -p 'process.versions.node')"

node -e '
  const want = process.argv[1].split(".").map(Number);
  const have = process.argv[2].split(".").map(Number);
  for (let i = 0; i < 3; i += 1) {
    if ((have[i] || 0) > (want[i] || 0)) process.exit(0);
    if ((have[i] || 0) < (want[i] || 0)) process.exit(1);
  }
  process.exit(0);
' 22.19.0 "$NODE_VERSION" || die "Node >= 22.19 is required (found $NODE_VERSION)"

if [ ! -f "$PROFILE_DIR/package.json" ]; then
  echo "creating profile '$PROFILE' from the web template"
  if [ "$PROFILE" = "web" ]; then
    dsh "$PROFILE" --help >/dev/null 2>&1 || true
  else
    dsh "$PROFILE" --from-default-profile web --help >/dev/null 2>&1 || true
  fi
  [ -f "$PROFILE_DIR/package.json" ] || die "could not create profile '$PROFILE'"
fi

has_bundle() {
  node -e '
    const pkg = require(process.argv[1]);
    const bundles = (pkg.dsh && pkg.dsh.profile && pkg.dsh.profile.bundles) || [];
    process.exit(bundles.some((name) => String(name).includes(process.argv[2])) ? 0 : 1);
  ' "$PROFILE_DIR/package.json" "$1"
}

has_bundle "dsh-web-app" || echo "warning: profile '$PROFILE' does not bundle the harness web app; the gate will not start"

run_limited() {
  local seconds="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$seconds" "$@"
  else
    "$@"
  fi
}

REVISION=""
if command -v git >/dev/null 2>&1; then
  REFS="$(run_limited 30 git ls-remote "https://github.com/$REPO.git" \
    "refs/tags/$VERSION" "refs/tags/$VERSION^{}" 2>/dev/null || true)"
  REVISION="$(printf '%s\n' "$REFS" | awk -v tag="refs/tags/$VERSION" '
    $2 == tag { direct = $1 }
    $2 == tag "^{}" { peeled = $1 }
    END { if (peeled) print peeled; else if (direct) print direct }
  ')"
fi

if [ ${#REVISION} -eq 40 ] && [[ "$REVISION" != *[!0-9a-f]* ]]; then
  SOURCE_REF="$REVISION"
else
  echo "warning: could not resolve $VERSION to a commit; an update may use a cached copy" >&2
  SOURCE_REF="refs/tags/$VERSION"
  REVISION="$VERSION"
fi

echo "installing dsh-frontgate $VERSION into profile '$PROFILE'"
ARCHIVE="https://codeload.github.com/$REPO/tar.gz/$SOURCE_REF"

if ! run_limited 300 dsh plugin --profile "$PROFILE" add "$ARCHIVE"; then
  echo "archive install failed, retrying with git"
  run_limited 180 dsh plugin --profile "$PROFILE" add "github:$REPO#$REVISION" \
    || die "installation failed; run 'dsh plugin --profile $PROFILE add github:$REPO#$VERSION' manually"
fi

has_bundle "dsh-frontgate" || die "the plugin was installed but not registered in $PROFILE_DIR/package.json"

cat <<EOF

dsh-frontgate $VERSION is installed in profile '$PROFILE'.

Restart the harness process that serves this profile, then open the gate.
The gate listens on 127.0.0.1:3090 by default. When no password is configured
or saved, the first start prints PASSWORD: xxxx-xxxx-xxxx-xxxx to stderr.

To expose it on the network, set listenHost and listenPort in
$PROFILE_DIR/cordis.patch.yml.
EOF
