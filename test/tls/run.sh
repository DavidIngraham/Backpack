#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
python3 -m unittest discover -s test/tls -p 'test_*.py'
mbedtls=.pio/host-mbedtls
if [[ ! -d "$mbedtls" ]]; then
    git -c advice.detachedHead=false clone --quiet --depth 1 --branch v2.28.7 https://github.com/Mbed-TLS/mbedtls.git "$mbedtls"
fi
[[ $(git -C "$mbedtls" rev-parse HEAD) == 555f84735aecdbd76a566cf087ec8425dfb0c8ab ]]
cmake -S "$mbedtls" -B "$mbedtls/build" -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF >/dev/null
cmake --build "$mbedtls/build" -j4 >/dev/null
build_dir=$(mktemp -d)
trap 'rm -rf -- "$build_dir"' EXIT
python3 python/provision_tls.py --out "$build_dir/first" --hostname elrs-test.local >/dev/null
python3 python/provision_tls.py --out "$build_dir/second" --hostname elrs-test.local --ca-dir "$build_dir/first/ca" >/dev/null
flags=(-std=c++11 -Wall -Wextra -Werror -g -fsanitize=address,undefined -fno-omit-frame-pointer
       -Ilib/WIFI -I"$mbedtls/include" -I.pio/libdeps/ESP32C3_TX_Backpack_via_UART/ArduinoJson/src)
libs=("$mbedtls/build/library/libmbedx509.a" "$mbedtls/build/library/libmbedcrypto.a")
g++ "${flags[@]}" test/tls/credentials_test.cpp "${libs[@]}" -o "$build_dir/credentials_test"
"$build_dir/credentials_test" "$build_dir/first/backpack-tls.json" "$build_dir/second/backpack-tls.json"
g++ "${flags[@]}" -Itest/tls/stubs test/tls/server_test.cpp "${libs[@]}" -o "$build_dir/server_test"
"$build_dir/server_test" "$build_dir/first/backpack-tls.json"
