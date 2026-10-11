#include "HttpMocks.h"
#include "MavlinkWebSocket.h"
#include <fstream>
#include <iterator>
#include <cstdio>
static void disconnect(httpd_req_t &r) {
    if (r.free_ctx && r.sess_ctx) r.free_ctx(r.sess_ctx);
    r.sess_ctx = nullptr;
}
static void authorize(httpd_req_t &r) {
    r.origin = mavtls::credentials->origin;
    r.query = "token=" + mavtls::credentials->token;
}
static void upload(AsyncWebServerRequest &r, std::string &bundle) {
    mavtls::upload(&r, "bundle.json", 0, reinterpret_cast<uint8_t *>(&bundle[0]), bundle.size(), true);
    mavtls::uploaded(&r);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    std::ifstream file(argv[1]); std::string bundle{std::istreambuf_iterator<char>(file), {}};
    AsyncWebServer server;
    AsyncWebServerRequest rejected;
    upload(rejected, bundle); assert(rejected.code == 400 && testNvsBlob.empty());
    mavtls::provisioningAllowed.store(true);
    AsyncWebServerRequest crossOrigin; crossOrigin.headers["Origin"].text = "https://evil.example";
    upload(crossOrigin, bundle); assert(crossOrigin.code == 400 && testNvsBlob.empty());
    AsyncWebServerRequest interrupted, concurrent;
    mavtls::upload(&interrupted, "bundle", 0, reinterpret_cast<uint8_t *>(&bundle[0]), 30, false);
    upload(concurrent, bundle); assert(concurrent.code == 400);
    interrupted.disconnect(); assert(!mavtls::uploadOwner && !mavtls::uploadBuffer);
    AsyncWebServerRequest multiple;
    auto *bytes = reinterpret_cast<uint8_t *>(&bundle[0]);
    mavtls::upload(&multiple, "one", 0, bytes, bundle.size(), true);
    mavtls::upload(&multiple, "two", 0, bytes, bundle.size(), true);
    mavtls::uploaded(&multiple); assert(multiple.code == 400 && testNvsBlob.empty());
    AsyncWebServerRequest failed; testNvsFail = true;
    upload(failed, bundle); assert(failed.code == 500 && testNvsBlob.empty()); testNvsFail = false;
    AsyncWebServerRequest saved; upload(saved, bundle);
    assert(saved.code == 200 && testNvsBlob == bundle && mavtls::restartNeeded.load()); saved.disconnect();
    mavtls::restartNeeded.store(false); // Simulated reboot: NVS survives.
    StartMavlinkWebSocket(server);
    assert(mavtls::credentials && mavtls::serverRunning.load());
    assert(testRoutes.size() == 3);
    httpd_req_t preflight; preflight.origin = mavtls::credentials->origin;
    assert(testRoutes[2].method == http_method::HTTP_OPTIONS);
    assert(testRoutes[2].handler(&preflight) == ESP_OK);
    preflight.origin = "https://evil.example";
    assert(testRoutes[2].handler(&preflight) == ESP_FAIL);
    AsyncWebServerRequest status; mavtls::status(&status);
    assert(status.body.find(mavtls::credentials->token) == std::string::npos);
    assert(status.body.find("PRIVATE KEY") == std::string::npos);
    httpd_req_t r; authorize(r);
    assert(mavtls::websocket(&r) == ESP_FAIL); // Telemetry disabled.
    PollMavlinkWebSocket(true);
    r.origin = "https://evil.example"; assert(mavtls::websocket(&r) == ESP_FAIL);
    authorize(r); r.query = "token=bad"; assert(mavtls::websocket(&r) == ESP_FAIL);
    authorize(r); assert(mavtls::websocket(&r) == ESP_OK);
    httpd_req_t second; authorize(second); assert(mavtls::websocket(&second) == ESP_FAIL);
    uint8_t data[] = {1, 2, 3};
    r.method = http_method::HTTP_POST; r.incoming.type = HTTPD_WS_TYPE_BINARY;
    r.incoming.final = false; r.incoming.payload = data; r.incoming.len = 2;
    assert(mavtls::websocket(&r) == ESP_OK); PollMavlinkWebSocket(true); assert(mavlink.input.empty());
    r.incoming.type = HTTPD_WS_TYPE_CONTINUE; r.incoming.final = true; r.incoming.len = 1; r.incoming.payload = data + 2;
    assert(mavtls::websocket(&r) == ESP_OK); PollMavlinkWebSocket(true);
    assert(mavlink.input == std::vector<uint8_t>({1, 2, 3}) && mavlink.resets == 1);
    r.incoming.type = HTTPD_WS_TYPE_PING; r.incoming.len = 0; r.reads = 0;
    assert(mavtls::websocket(&r) == ESP_OK && r.reads == 1); // No second zero-length recv.
    SendMavlinkWebSocket(data, 3); mavtls::pump(nullptr); assert(testDownlink.size() == 3);
    // Old queued commands and output never reach a new client with the same fd.
    r.incoming.type = HTTPD_WS_TYPE_BINARY; r.incoming.len = 1; r.incoming.payload = data;
    assert(mavtls::websocket(&r) == ESP_OK); SendMavlinkWebSocket(data, 3); disconnect(r);
    assert(mavtls::websocket(&second) == ESP_OK); PollMavlinkWebSocket(true); mavtls::pump(nullptr);
    assert(mavlink.input.size() == 3 && testDownlink.size() == 3);
    second.method = http_method::HTTP_POST; second.incoming = r.incoming;
    assert(mavtls::websocket(&second) == ESP_OK); PollMavlinkWebSocket(true); assert(mavlink.resets == 2);
    for (int i = 0; i < 33; ++i) SendMavlinkWebSocket(data, 3);
    mavtls::pump(nullptr); assert(testCloseCode == 1013 && !mavtls::activeSession.load()); disconnect(second);
    httpd_req_t third; authorize(third); assert(mavtls::websocket(&third) == ESP_OK);
    third.method = http_method::HTTP_POST; third.incoming = r.incoming;
    for (int i = 0; i < 4; ++i) assert(mavtls::websocket(&third) == ESP_OK);
    assert(mavtls::websocket(&third) == ESP_FAIL && testCloseCode == 1013);
    disconnect(third); PollMavlinkWebSocket(true); assert(mavlink.input.size() == 4);
    httpd_req_t fourth; authorize(fourth); assert(mavtls::websocket(&fourth) == ESP_OK);
    PollMavlinkWebSocket(false); mavtls::pump(nullptr); assert(!mavtls::activeSession.load()); disconnect(fourth);
    vQueueDelete(mavtls::inputQueue); vQueueDelete(mavtls::outputQueue);
    puts("TLS provisioning, persistence, auth, reconnect and queue lifecycle tests passed");
}
