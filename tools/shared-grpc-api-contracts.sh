#!/usr/bin/env bash
set -euo pipefail

# Immutable source pin for firmware and console generation.
SHARED_GRPC_API_CONTRACTS_REF="da25fbb4f289abf7133432ba69156235e449f151"
SHARED_GRPC_API_CONTRACTS_INPUT="https://github.com/wendylabsinc/service-protos.git#ref=$SHARED_GRPC_API_CONTRACTS_REF"
SHARED_GRPC_API_CONTRACTS_PROTOS=(
    "wendylite/v1/wendy_com_msg.proto"
    "wendylite/v1/sensorlink.proto"
)

check_shared_grpc_api_contracts_ancestry() (
    local scratch
    scratch="$(mktemp -d)"
    trap 'rm -rf "$scratch"' EXIT
    # As in WendyOS, policy comes from authoritative main independently of the pin.
    curl --fail --silent --show-error --location \
        https://raw.githubusercontent.com/wendylabsinc/service-protos/main/tools/check-pin.sh \
        --output "$scratch/check-pin.sh"
    bash "$scratch/check-pin.sh" "$SHARED_GRPC_API_CONTRACTS_REF"
)

export_shared_grpc_api_contracts() {
    local output="$1" root proto alias
    local path_args=()
    root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    for proto in "${SHARED_GRPC_API_CONTRACTS_PROTOS[@]}"; do
        for alias in "$proto" "${proto##*/}"; do
            if [[ -e "$root/components/wendy_com/proto/$alias" || -L "$root/components/wendy_com/proto/$alias" ]]; then
                echo "error: remove components/wendy_com/proto/$alias; its source is in pinned service-protos" >&2
                return 1
            fi
        done
        path_args+=(--path "$proto")
    done
    buf export "$SHARED_GRPC_API_CONTRACTS_INPUT" "${path_args[@]}" --output "$output"
    for proto in "${SHARED_GRPC_API_CONTRACTS_PROTOS[@]}"; do
        if [[ ! -f "$output/$proto" ]]; then
            echo "error: selected shared proto missing from export: $proto" >&2
            return 1
        fi
    done
}

case "$#:${1:-}" in
    1:--check-pin) check_shared_grpc_api_contracts_ancestry ;;
    2:--export) export_shared_grpc_api_contracts "$2" ;;
    *) echo "usage: bash $0 --check-pin | --export <directory>" >&2; exit 1 ;;
esac
