#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${1:?pass an output directory outside the checkout}
mkdir -p "$out"
compiler=${SWIFTC:-swiftc}
if test "$(uname -s)" = Darwin; then
    service_test_sdk=$(xcrun --sdk macosx --show-sdk-path)
    service_test_target=$(uname -m)-apple-macosx15.0
    clang -target "$service_test_target" -isysroot "$service_test_sdk" -std=c11 -Wall -Wextra -Werror -I "$root/tests/ServiceReplay" -c "$root/tests/ServiceReplay/host.c" -o "$out/host.o"
    set -- -sdk "$service_test_sdk" -target "$service_test_target"
else
    clang -std=c11 -Wall -Wextra -Werror -I "$root/tests/ServiceReplay" -c "$root/tests/ServiceReplay/host.c" -o "$out/host.o"
    set --
fi
"$compiler" "$@" -I "$root/tests/ServiceReplay" "$root/Sources/WendyLite/Internal.swift" "$root/Sources/WendyLite/Services.swift" "$root/tests/ServiceReplay/main.swift" "$out/host.o" -o "$out/service-replay-swift-test"
"$out/service-replay-swift-test"
