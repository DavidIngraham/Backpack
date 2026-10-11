# MAVLink transport tests

Run from the repository root after installing the ESP32-C3 dependencies:

```sh
pio pkg install -e ESP32C3_TX_Backpack_via_UART
bash test/websocket/run.sh
```

This links production `MAVLink.cpp` against the pinned MAVLink library and
checks binary v1/v2 round trips, interleaved UDP/WebSocket input, multiple
packets per message and parser reset across translation units. It uses
AddressSanitizer and UndefinedBehaviorSanitizer. Set `MAVLINK_INCLUDE` to use
another installed copy of the MAVLink headers.

WSS bridge lifecycle and credential tests now live in `test/tls`. These host
tests do not replace target builds or hardware/concurrency testing.
