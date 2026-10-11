#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
mavlink="${MAVLINK_INCLUDE:-.pio/libdeps/ESP32C3_TX_Backpack_via_UART/c_library_v2}"
if [[ ! -f "$mavlink/common/mavlink.h" ]]; then
    echo 'Install target dependencies first: pio pkg install -e ESP32C3_TX_Backpack_via_UART' >&2
    exit 1
fi
build_dir=$(mktemp -d)
trap 'rm -rf -- "$build_dir"' EXIT
flags=(-std=c++11 -Wall -Wextra -Werror -g -fsanitize=address,undefined -fno-omit-frame-pointer -Itest/websocket/stubs)
g++ "${flags[@]}" -Wno-address-of-packed-member -DMAVLINK_ENABLED=1 \
    -isystem "$mavlink" -Ilib/MAVLink test/websocket/mavlink_test.cpp \
    lib/MAVLink/MAVLink.cpp -o "$build_dir/mavlink_test"
"$build_dir/mavlink_test"
