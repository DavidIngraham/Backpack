# TLS provisioning and WSS tests

From the repository root, with the ESP32-C3 PlatformIO dependencies installed:

```sh
bash test/tls/run.sh
```

Requires Linux, Python 3.10+, OpenSSL 1.1.1+, Git, CMake, a C/C++ compiler and
sanitizer support. The first run downloads and builds pinned mbedTLS 2.28.7
(the firmware's version) under `.pio/host-mbedtls`. Tests use the actual
ArduinoJson dependency installed by PlatformIO. CI runs this suite after the
ESP32-C3 build.

- Python tests generate and renew credentials, inspect the Apple profile for
  public-only content, reject bad names/keys and perform real local TLS
  handshakes for trusted/untrusted roots, DNS names and the AP IP SAN.
- C++ credential tests use real mbedTLS and ArduinoJson to validate bundles,
  key matching, SANs, bounds, malformed input, token checks and frame assembly.
- C++ server tests compile the production WSS and provisioning headers with
  simulated ESP-IDF, AsyncHTTP, NVS and FreeRTOS APIs. They cover provisioning
  restrictions, failed writes, disconnect/upload ownership, authorization,
  fragmentation, parser resets, reused sockets, queue limits and mode changes.
- Both C++ executables run with AddressSanitizer and UndefinedBehaviorSanitizer.

Mocks cannot prove ESP task scheduling, device heap/stack headroom, real radio
throughput or Safari/PWA behavior. The Python TLS server verifies generated
certificates, not the ESP-IDF network implementation. Build the target firmware
and complete the physical validation checklist in `docs/mavlink-websocket.md`.
