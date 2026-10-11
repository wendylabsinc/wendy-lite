#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# The superproject gitlink already pins wolfSSL. Keep this explicit review gate
# in sync when deliberately upgrading the cryptographic dependency.
# wolfSSL v5.9.1-stable (the commit, not the annotated tag object).
expected=1d363f3adceba9d1478230ede476a37b0dcdef24
path=components/wendy_wolfssl/wolfssl
recorded=$(git rev-parse "HEAD:$path")
checked_out=$(git -C "$path" rev-parse HEAD)

if [[ "$recorded" != "$expected" || "$checked_out" != "$expected" ]]; then
    printf 'wolfSSL revision mismatch: expected %s, gitlink %s, checkout %s\n' \
        "$expected" "$recorded" "$checked_out" >&2
    exit 1
fi
