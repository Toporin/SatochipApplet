#!/usr/bin/env bash
#
# Compares the performance of two applet commits on a real card.
#
# For each revision, builds the CAP in a temporary git worktree (the current checkout is not
# touched), then installs each CAP in turn on the card and runs the `benchmarkCard` Gradle task
# (src/test/java/org/satochip/applet/SatochipBenchmark.java), which times the Schnorr and MuSig2
# commands plus two control commands. Rounds alternate the order of the revisions (A B, then B A)
# to cancel slow drift. Finally prints the median of each operation per revision, and the ratio.
#
# WARNING: every install DELETES the applet and all its data (seed, keys, PIN) on the card.
# Use a spare development card. At the end, the card holds TARGET_REV: run `./gradlew install`
# to put the current checkout back.
#
# Usage: scripts/benchmark-commits.sh [--yes] [--build-only] [-n ITER] [-r ROUNDS] BASE_REV TARGET_REV
#   --yes         do not ask for confirmation before installing on the card
#   --build-only  only build the two CAPs, do not touch the card
#   -n ITER       timed iterations per operation and round (default 50)
#   -r ROUNDS     rounds, each measuring both revisions (default 2)
# Example: scripts/benchmark-commits.sh 87761e9^ 87761e9

set -euo pipefail

usage() { sed -n '/^# Usage:/,/^# Example:/p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

YES=0; BUILD_ONLY=0; ITER=50; ROUNDS=2
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) YES=1 ;;
    --build-only) BUILD_ONLY=1 ;;
    -n) ITER="$2"; shift ;;
    -r) ROUNDS="$2"; shift ;;
    -h|--help) usage ;;
    -*) echo "Unknown option: $1" >&2; usage ;;
    *) break ;;
  esac
  shift
done
[ $# -eq 2 ] || usage

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
command -v python3 >/dev/null || { echo "python3 is required for the report" >&2; exit 1; }
[ -d "$ROOT/sdks/jc320v25.0_kit" ] || {
  echo "The sdks submodule is not initialized: git submodule update --init --recursive" >&2; exit 1; }

BASE="$(git rev-parse --short "$1^{commit}")"
TARGET="$(git rev-parse --short "$2^{commit}")"
REVS=("$BASE" "$TARGET")

OUT="$ROOT/build/benchmark/run-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT/caps"

TMP="$(mktemp -d)"
cleanup() {
  for rev in "${REVS[@]}"; do
    [ -d "$TMP/$rev" ] && git -C "$ROOT" worktree remove --force "$TMP/$rev" 2>/dev/null || true
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

# --- 1. build a CAP per revision, each in its own worktree -----------------------------------
for rev in "${REVS[@]}"; do
  echo "=== Building the CAP of $rev ($(git log -1 --format=%s "$rev"))"
  wt="$TMP/$rev"
  git worktree add --detach --quiet "$wt" "$rev"
  # the submodule is not checked out in the worktree: reuse the initialized one
  rm -rf "$wt/sdks"
  ln -s "$ROOT/sdks" "$wt/sdks"
  (cd "$wt" && ./gradlew convertJavacard -q --no-watch-fs)
  cp "$wt/build/javacard/org/satochip/applet/javacard/applet.cap" "$OUT/caps/$rev.cap"
done
echo "CAPs: $OUT/caps"
if [ "$BUILD_ONLY" -eq 1 ]; then
  exit 0
fi

# --- 2. install and measure, alternating the order of the revisions ---------------------------
if [ "$YES" -ne 1 ]; then
  echo
  echo "Each of the $((2 * ROUNDS)) installs DELETES the applet and all its data on the card in the reader."
  read -r -p "Use a spare development card. Continue? [y/N] " answer
  [ "$answer" = "y" ] || [ "$answer" = "Y" ] || { echo "Aborted."; exit 1; }
fi

for round in $(seq 1 "$ROUNDS"); do
  if [ $((round % 2)) -eq 1 ]; then order=("$BASE" "$TARGET"); else order=("$TARGET" "$BASE"); fi
  for rev in "${order[@]}"; do
    echo "=== Round $round/$ROUNDS: $rev"
    ./gradlew install -q -Porg.satochip.install.cap="$OUT/caps/$rev.cap"
    ./gradlew benchmarkCard \
      -Porg.satochip.bench.label="$rev-r$round" \
      -Porg.satochip.bench.iterations="$ITER" \
      -Porg.satochip.bench.out="$OUT"
  done
done

# --- 3. report ----------------------------------------------------------------------------------
python3 - "$OUT" "$BASE" "$TARGET" <<'EOF'
import csv, glob, os, statistics, sys

out, base, target = sys.argv[1:4]
samples = {}  # (revision, operation) -> [micros]
operations = []
for path in sorted(glob.glob(os.path.join(out, "*.csv"))):
    with open(path) as f:
        for row in csv.DictReader(f):
            rev = row["label"].rsplit("-r", 1)[0]
            op = row["operation"]
            if op not in operations:
                operations.append(op)
            samples.setdefault((rev, op), []).append(int(row["micros"]))

print()
print(f"Median per operation, in ms (all rounds merged). BASE={base} TARGET={target}")
print(f"{'operation':<22} {'n':>5} {'BASE':>9} {'TARGET':>9} {'delta':>9} {'ratio':>7}")
for op in operations:
    a, b = samples.get((base, op), []), samples.get((target, op), [])
    if not a or not b:
        continue
    ma, mb = statistics.median(a) / 1000, statistics.median(b) / 1000
    print(f"{op:<22} {min(len(a), len(b)):>5} {ma:>9.2f} {mb:>9.2f} {mb - ma:>+9.2f} {mb / ma:>7.2f}")
print()
print("The control operations should have a ratio close to 1.00; if not, the measurement is drifting.")
print(f"Raw samples: {out}")
EOF

echo
echo "The card now holds $TARGET. Run ./gradlew install to put the current checkout back."
