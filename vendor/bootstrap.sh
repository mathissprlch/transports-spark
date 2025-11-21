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

cd "$AWS_DIR"

# Reset to the pinned commit on a local branch so subsequent applies are clean.
echo "==> checkout pin $AWS_PIN"
git fetch --quiet origin "$AWS_PIN"
git checkout --quiet -B grpc-ada "$AWS_PIN"

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

echo "==> AWS ready at $AWS_DIR"
