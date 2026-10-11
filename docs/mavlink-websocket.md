# MAVLink over secure WebSockets

Secure WebSockets let browser-based ground control stations, such as Lofty GCS,
send and receive MAVLink telemetry through the TX Backpack.

ESP32-C3 TX Backpack firmware provides a TLS WebSocket endpoint on
port 443: `wss://<paired-hostname>.local/mavlink/ws?token=<pairing-token>`.
Enable MAVLink Wi-Fi telemetry to accept a connection. The existing HTTP
configuration page, `/mavlink` statistics and UDP forwarding remain available.
ESP8266/ESP8285 builds do not include WSS.

Open your GCS in a browser and connect to this endpoint after setting up the
Backpack's certificate. Installing the GCS as a PWA is optional. For use without
internet access, check that your GCS supports offline use and prepare any maps
you need before connecting to the Backpack.

## Set up a browser connection

1. Choose a GCS that supports binary MAVLink over WebSockets, such as Lofty GCS.
   Open it over HTTPS and note its origin for the next step.
2. On a computer with Python 3.10+ and OpenSSL 1.1.1+, generate credentials:

   ```sh
   python3 python/provision_tls.py --out ~/backpack-pairing \
     --hostname my-backpack.local --origin https://gcs.loftedaero.com
   ```

   Use the **actual HTTPS origin** of your GCS, including a non-default port if
   applicable, without a path or trailing slash. Only that origin is accepted.
   Use a distinct hostname for each Backpack.
3. Put the Backpack into its existing Wi-Fi firmware-update AP mode. Connect
   directly to its Wi-Fi, open `http://10.0.0.1`, then the **MavLink** tab. Upload
   `backpack-tls.json` in the TLS section. Check the displayed result and restart
   using the provided control. Credential writes are disabled in telemetry or
   station mode and during firmware updates.
4. On an iPad, transfer `backpack.mobileconfig` and install its profile in
   Settings. Enable full trust for your personal Backpack CA under **Settings →
   General → About → Certificate Trust Settings**. See Apple's
   [manual certificate trust instructions](https://support.apple.com/en-us/102390).
   Installing a certificate on the Backpack alone cannot establish browser trust.
   Other platforms must trust `trust-ca.pem` in the certificate store used by
   their browser.
5. Enable MAVLink Wi-Fi telemetry and join the Backpack Wi-Fi (or the same station
   network). Visit `https://my-backpack.local/` to check TLS trust. It should show
   a short status message without a certificate warning. The configured hostname
   replaces the default Backpack mDNS hostname; HTTP configuration remains
   accessible by IP address.
6. Paste the URL from `connection.txt` into your GCS's WebSocket connection settings.
   Allow local-network access if the browser requests it. In AP mode,
   `connection-ap.txt` supplies an alternative using `10.0.0.1` if mDNS resolution
   is unavailable. Generated certificates include that IP SAN; an imported
   certificate must include it to use the IP URL. Arbitrary station IP addresses
   do not match the generated certificate.
7. Verify heartbeats and parameter reads before parameter writes.

If the GCS uses a Content Security Policy, its `connect-src` policy must allow
the Backpack endpoint. Browser local-network permissions also apply. The endpoint
supports an origin-restricted private-network OPTIONS preflight for browsers
that use one.

## Certificates and pairing

The helper creates an individual EC P-256 server key/certificate, a random
256-bit pairing token and a personal CA. The server certificate lasts 365 days;
the CA lasts ten years. `backpack.mobileconfig` contains only the public CA
certificate. Keep the CA private key on your computer, never on the Backpack or
in the GCS. Protect the output directory, JSON bundle and connection URLs: they
contain private material or a token authorizing MAVLink commands.

Renew before expiry using the same CA and hostname, then upload the new bundle
in AP update mode and replace the saved GCS URL. Reusing the CA avoids another
trust installation; the device key and token rotate:

```sh
python3 python/provision_tls.py --out ~/backpack-renewal \
  --ca-dir ~/backpack-pairing/ca --hostname my-backpack.local \
  --origin https://gcs.loftedaero.com
```

For an existing certificate, supply `--cert server-chain.pem --key server-key.pem`
and optionally `--ca-cert root-ca.pem` to generate an Apple trust profile. The
leaf must have the exact configured DNS SAN, serverAuth EKU, digitalSignature
key usage and a matching unencrypted private key. Firmware accepts EC keys of
at least 256 bits or RSA keys of at least 2048 bits, with SHA-256/384/512
signatures. Bundle, certificate-chain and private-key limits are 8192, 4096 and
2048 bytes respectively. EC P-256 is recommended for this device.

Validated credentials are committed as one NVS blob and activated on restart.
An invalid upload leaves saved credentials unchanged. Normal OTA updates retain
NVS credentials; a full flash erase removes them. **Remove TLS credentials** in
the configuration page clears them, then requires a restart. No credentials
means WSS is disabled. Public status includes fingerprint, expiry and startup
errors, but never returns the private key or pairing token.

Initial provisioning uses the existing HTTP configuration server over the
Backpack's Wi-Fi AP. Use a trusted direct AP connection; the upload is not
end-to-end TLS protected. Credentials are stored in ordinary NVS, without
additional at-rest encryption. Same-origin checks restrict browser writes;
physical AP/update-mode access remains the provisioning authority. TLS
authenticates the device and protects WSS traffic; the origin check and token
authorize the GCS. This does not add authentication to the existing UDP bridge.

## WebSocket protocol

- One authorized browser client at a time; no WebSocket subprotocol.
- Binary MAVLink v1/v2 bytes in both directions. Each outgoing message contains
  one MAVLink packet. Incoming messages may contain multiple or partial packets.
- Binary continuation frames are supported, with a 1024-byte complete-message
  limit. Text closes with 1003, malformed fragmentation with 1002, oversize with
  1009 and queue saturation/service shutdown with 1013.
- Four input messages and 32 output packets bound memory use. TLS socket I/O
  runs in the ESP-IDF HTTPS task, outside the UART loop. A separate scheduler
  queues output work; session IDs prevent fd reuse from delivering stale data.
- UART writes and MAVLink parser resets run in the firmware loop. Reconnecting
  starts a fresh parser. Mode changes discard pending commands. Do not replay
  aircraft commands automatically after reconnecting.
- The bundled ESP-IDF 4.4 server upgrades before calling the WebSocket handler.
  Invalid origin/token, unavailable telemetry or a second client therefore get
  an immediate connection close, before session allocation or command handling,
  rather than a pre-upgrade HTTP authentication error.
- UDP and WSS have separate input parsers and can both send commands; control
  ownership is not arbitrated. Use MAVLink heartbeats to assess the aircraft link.

HTTP provisioning uses ESPAsyncWebServer; WSS uses the bundled ESP-IDF HTTPS
server and mbedTLS. Offline firmware may lack a trusted wall clock, so browsers
always enforce certificate validity even when device-side date checks cannot.

## Build and validate

```sh
pio run -e ESP32C3_TX_Backpack_via_UART -e ESP_TX_Backpack_via_UART
bash test/tls/run.sh
bash test/websocket/run.sh
```

The TX15 target is `ESP32C3_TX_Backpack`. Firmware is emitted at
`.pio/build/<environment>/firmware.bin`; these commands do not flash hardware.
The ESP8285 target is a regression build and has no WSS endpoint. See
`test/tls/README.md` for test coverage and prerequisites.

Before operational use, bench-test with your radio and browser: trusted HTTPS/WSS,
heartbeat reception, parameter reads/writes, mission
transfer, reconnects, sleep/wake, slow clients, concurrent UDP, TLS heap/stack
headroom and an OTA update retaining credentials. Host tests and successful
firmware builds do not establish hardware or flight validation.
