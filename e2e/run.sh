#!/usr/bin/env bash
#
# Local end-to-end run of hsm, gatekeeper and railgate. Starts nothing
# remotely and deploys nothing: the test starts the three already-built fat
# jars as child processes on free loopback ports and stops them afterwards.
#
# Usage: ./run.sh [extra Maven arguments, e.g. -De2e.positive.file=...]

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEKEEPER="$(cd "$HERE/.." && pwd)"
REPOS="$(cd "$GATEKEEPER/.." && pwd)"
VERSION="1.5.0"

missing=()
repo_dir() {
    if [[ "$1" == "gatekeeper" ]]; then echo "$GATEKEEPER"; else echo "$REPOS/$1"; fi
}

for service in gatekeeper hsm railgate; do
    jar="$(repo_dir "$service")/target/$service-$VERSION.jar"
    if [[ ! -f "$jar" ]]; then
        missing+=("$jar")
    fi
done

if (( ${#missing[@]} > 0 )); then
    echo "The end-to-end test needs the three fat jars. Missing:" >&2
    for jar in "${missing[@]}"; do
        echo "  $jar" >&2
    done
    echo >&2
    echo "Build them first:" >&2
    echo "  (cd \"$GATEKEEPER\" && mvn verify)" >&2
    echo "  (cd \"$REPOS/hsm\" && mvn verify)" >&2
    echo "  (cd \"$REPOS/railgate\" && mvn verify)" >&2
    exit 1
fi

for tool in java mvn; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "'$tool' is not on PATH." >&2
        exit 1
    fi
done

PIDS="$HERE/target/e2e-logs/pids"

stop_leftovers() {
    [[ -f "$PIDS" ]] || return 0
    while read -r pid jar; do
        [[ -n "${pid:-}" && -n "${jar:-}" ]] || continue
        if ps -p "$pid" -o command= 2>/dev/null | grep -qF -- "$jar"; then
            echo "Stopping leftover process $pid ($jar)" >&2
            kill "$pid" 2>/dev/null || true
            sleep 2
            kill -9 "$pid" 2>/dev/null || true
        fi
    done < "$PIDS"
}

stop_leftovers
rm -f "$PIDS"
trap stop_leftovers EXIT

cd "$HERE"
mvn -B verify "$@"
