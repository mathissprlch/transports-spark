#!/usr/bin/env sh
# Clone AWS at the pinned commit and apply our trailer patches.
# Idempotent: re-run after a pin bump or patch change.

set -eu

VENDOR_DIR="$(cd "$(dirname "$0")" && pwd)"
AWS_DIR="$VENDOR_DIR/aws"
PATCH_DIR="$VENDOR_DIR/aws-patches"

# Pinned upstream. Bump deliberately; patches assume this tree.
AWS_REMOTE="https://github.com/AdaCore/aws.git"
AWS_PIN="483739e49a4745d92942d86ec730fcf7214476c5"

if [ ! -d "$AWS_DIR" ]; then
  echo "==> cloning AWS"
  git clone "$AWS_REMOTE" "$AWS_DIR"
fi

# Pick the correct os_lib.ads overlay for this host. AWS normally generates
# this by running `clang/gcc + xoscons` against SDK headers (see
# docs/aws-integration.md). We ship pre-generated overlays per platform so
# every developer gets identical constants without needing OpenSSL headers
# locally.
OVERLAY=""
case "$(uname -sm)" in
  "Darwin arm64") OVERLAY="darwin-arm64-openssl" ;;
  "Darwin x86_64") OVERLAY="darwin-x86_64-openssl" ;;
  Linux\ x86_64)  OVERLAY="linux-x86_64-openssl" ;;
esac

cd "$AWS_DIR"

# Reset to the pinned commit on a local branch so subsequent applies are clean.
echo "==> checkout pin $AWS_PIN"
git fetch --quiet origin "$AWS_PIN"
git reset --quiet --hard "$AWS_PIN"
git checkout --quiet -B grpc-ada

# Apply patches in order. `git apply --check` first so we fail loudly.
if [ -d "$PATCH_DIR" ]; then
  for p in "$PATCH_DIR"/*.patch; do
    [ -f "$p" ] || continue
    echo "==> applying $(basename "$p")"
    if ! git apply --check "$p" 2>/dev/null; then
      echo "    already applied or conflicting — skipping check"
    fi
    git apply "$p" || {
      echo "    apply failed for $p"; exit 1;
    }
    git add -A
    git -c user.email=patches@grpc-ada -c user.name="grpc-ada bootstrap" \
        commit -q -m "vendor: $(basename "$p" .patch)"
  done
fi

if [ -n "$OVERLAY" ]; then
  OVERLAY_DIR="$VENDOR_DIR/aws-overlays/$OVERLAY"
  if [ -f "$OVERLAY_DIR/os_lib.ads" ]; then
    DEST="$AWS_DIR/darwin-arm64/setup/src"
    case "$OVERLAY" in
      linux-*)        DEST="$AWS_DIR/x86_64-pc-linux-gnu/setup/src" ;;
      darwin-x86_64-*) DEST="$AWS_DIR/darwin-x86_64/setup/src" ;;
    esac
    mkdir -p "$DEST"
    cp "$OVERLAY_DIR/os_lib.ads" "$DEST/os_lib.ads"
    echo "==> installed os_lib.ads overlay ($OVERLAY)"
  fi
else
  echo "==> WARNING: no os_lib.ads overlay for $(uname -sm); see docs/aws-integration.md"
fi

echo "==> AWS ready at $AWS_DIR"
