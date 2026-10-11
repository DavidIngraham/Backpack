#pragma once
#include "TlsProvisioning.h"
#include "TlsWebSocketCore.h"
#include <esp_https_server.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>
#include <new>

namespace mavtls {
static httpd_handle_t server = nullptr;
static QueueHandle_t inputQueue = nullptr, outputQueue = nullptr;
static std::atomic<bool> enabled{false}, workPending{false};
static std::atomic<uint32_t> activeSession{0}, closeSession{0};
struct Input { uint32_t session; uint16_t length; uint8_t data[MaxMessage]; };
struct Output { uint32_t session; uint16_t length; uint8_t data[MAVLINK_MAX_PACKET_LEN]; };
struct Session { uint32_t id; int fd; bool closing = false; Message message; };
// Only the HTTPS server task accesses this pointer or its socket.
static Session *client = nullptr;
static uint32_t nextSession = 0;
static void disconnected(void *ctx) {
    auto *session = static_cast<Session *>(ctx);
    uint32_t expected = session->id;
    activeSession.compare_exchange_strong(expected, 0);
    if (client == session) client = nullptr;
    delete session;
}
static void closeClient(uint16_t code, bool schedule = true) {
    if (!client || client->closing) return;
    client->closing = true;
    uint8_t payload[] = {uint8_t(code >> 8), uint8_t(code)};
    httpd_ws_frame_t frame{}; frame.type = HTTPD_WS_TYPE_CLOSE; frame.payload = payload; frame.len = 2;
    httpd_ws_send_frame_async(server, client->fd, &frame);
    activeSession.store(0);
    if (schedule) httpd_sess_trigger_close(server, client->fd);
}
static esp_err_t websocket(httpd_req_t *request) {
    if (request->method == http_method::HTTP_GET) {
        char origin[193]{}, query[80]{}, token[65]{};
        bool allowed = enabled.load() && !client && credentials &&
            httpd_req_get_hdr_value_str(request, "Origin", origin, sizeof(origin)) == ESP_OK &&
            credentials->origin == origin &&
            httpd_req_get_url_query_str(request, query, sizeof(query)) == ESP_OK &&
            httpd_query_key_value(query, "token", token, sizeof(token)) == ESP_OK &&
            tokenMatches(token, credentials->token);
        // IDF 4.4 upgrades before invoking this handler. Reject immediately,
        // before allocating session state or accepting a single command.
        if (!allowed) return ESP_FAIL;
        auto *session = new (std::nothrow) Session{};
        if (!session) return ESP_FAIL;
        if (++nextSession == 0) ++nextSession;
        session->id = nextSession; session->fd = httpd_req_to_sockfd(request);
        request->sess_ctx = session; request->free_ctx = disconnected;
        client = session; activeSession.store(session->id);
        return ESP_OK;
    }
    auto *session = static_cast<Session *>(request->sess_ctx);
    if (!session || session != client || !enabled.load() || activeSession.load() != session->id) return ESP_FAIL;
    httpd_ws_frame_t frame{};
    if (httpd_ws_recv_frame(request, &frame, 0) != ESP_OK) return ESP_FAIL;
    if (frame.len > MaxMessage) { closeClient(1009, false); return ESP_FAIL; }
    uint8_t data[MaxMessage]; frame.payload = data;
    // A zero-length frame was completely consumed by the header probe.
    if (frame.len && httpd_ws_recv_frame(request, &frame, sizeof(data)) != ESP_OK) return ESP_FAIL;
    if (frame.type == HTTPD_WS_TYPE_PING) {
        if (frame.len > 125 || !frame.final) return ESP_FAIL;
        frame.type = HTTPD_WS_TYPE_PONG;
        return httpd_ws_send_frame(request, &frame);
    }
    if (frame.type == HTTPD_WS_TYPE_PONG) return frame.len <= 125 && frame.final ? ESP_OK : ESP_FAIL;
    if (frame.type == HTTPD_WS_TYPE_CLOSE) { closeClient(1000, false); return ESP_FAIL; }
    const unsigned result = session->message.accept(frame.type, frame.final, data, frame.len);
    if (result > 1) { closeClient(result, false); return ESP_FAIL; }
    if (result == 1 && session->message.length) {
        Input input{}; input.session = session->id; input.length = session->message.length;
        memcpy(input.data, session->message.data, input.length);
        if (xQueueSend(inputQueue, &input, 0) != pdTRUE) { closeClient(1013, false); return ESP_FAIL; }
    }
    return ESP_OK;
}
static void pump(void *) {
    // TLS I/O runs in httpd's task. The UART loop only copies bounded messages.
    if (client && (!enabled.load() || closeSession.exchange(0) == client->id)) closeClient(1013);
    Output output;
    for (unsigned i = 0; i < 8 && xQueueReceive(outputQueue, &output, 0) == pdTRUE; ++i) {
        if (!client || !enabled.load() || output.session != activeSession.load() || output.session != client->id) continue;
        httpd_ws_frame_t frame{};
        frame.type = HTTPD_WS_TYPE_BINARY; frame.payload = output.data; frame.len = output.length;
        if (httpd_ws_send_frame_async(server, client->fd, &frame) != ESP_OK) { closeClient(1013); break; }
    }
    workPending.store(false);
}
static void scheduler(void *) {
    for (;;) {
        // Queueing a control message can block; isolate that from the UART loop.
        if (!workPending.exchange(true) && httpd_queue_work(server, pump, nullptr) != ESP_OK) workPending.store(false);
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}
static void startServer() {
    if (!credentials) return;
    inputQueue = xQueueCreate(4, sizeof(Input)); outputQueue = xQueueCreate(32, sizeof(Output));
    if (!inputQueue || !outputQueue) { startupError = "Insufficient memory for WSS queues."; goto failed; }
    {
        httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
        config.cacert_pem = reinterpret_cast<const uint8_t *>(credentials->certificate.c_str());
        config.cacert_len = credentials->certificate.size() + 1;
        config.prvtkey_pem = reinterpret_cast<const uint8_t *>(credentials->privateKey.c_str());
        config.prvtkey_len = credentials->privateKey.size() + 1;
        config.httpd.max_open_sockets = 2;
        config.httpd.lru_purge_enable = false;
        config.httpd.recv_wait_timeout = 2; config.httpd.send_wait_timeout = 1;
        if (httpd_ssl_start(&server, &config) != ESP_OK) { startupError = "TLS server startup failed."; goto failed; }
        httpd_uri_t ws{}; ws.uri = "/mavlink/ws"; ws.method = http_method::HTTP_GET;
        ws.handler = websocket; ws.is_websocket = true; ws.handle_ws_control_frames = true;
        httpd_uri_t health{}; health.uri = "/"; health.method = http_method::HTTP_GET;
        health.handler = [](httpd_req_t *request) -> esp_err_t {
            httpd_resp_set_type(request, "text/plain");
            httpd_resp_set_hdr(request, "Cache-Control", "no-store");
            return httpd_resp_sendstr(request, "Backpack TLS is working. Connect your PWA using its paired WSS URL.");
        };
        httpd_uri_t options{}; options.uri = "/mavlink/ws"; options.method = http_method::HTTP_OPTIONS;
        options.handler = [](httpd_req_t *request) -> esp_err_t {
            char origin[193]{};
            if (httpd_req_get_hdr_value_str(request, "Origin", origin, sizeof(origin)) != ESP_OK || credentials->origin != origin) return ESP_FAIL;
            httpd_resp_set_hdr(request, "Access-Control-Allow-Origin", credentials->origin.c_str());
            httpd_resp_set_hdr(request, "Access-Control-Allow-Methods", "GET");
            httpd_resp_set_hdr(request, "Access-Control-Allow-Private-Network", "true");
            httpd_resp_set_hdr(request, "Vary", "Origin");
            return httpd_resp_sendstr(request, "");
        };
        if (httpd_register_uri_handler(server, &ws) != ESP_OK || httpd_register_uri_handler(server, &health) != ESP_OK ||
            httpd_register_uri_handler(server, &options) != ESP_OK ||
            xTaskCreate(scheduler, "mavtls-pump", 3072, nullptr, 1, nullptr) != pdPASS) {
            startupError = "Unable to register WSS handlers or task."; httpd_ssl_stop(server); server = nullptr; goto failed;
        }
    }
    serverRunning.store(true); return;
failed:
    if (inputQueue) { vQueueDelete(inputQueue); inputQueue = nullptr; }
    if (outputQueue) { vQueueDelete(outputQueue); outputQueue = nullptr; }
}
} // namespace mavtls

static void StartMavlinkWebSocket(AsyncWebServer &http) {
    mavtls::setupProvisioning(http); mavtls::startServer();
}
static void PollMavlinkWebSocket(bool enabled) {
    using namespace mavtls;
    mavtls::enabled.store(enabled && !restartNeeded.load());
    static uint32_t parserSession = 0;
    Input input;
    for (unsigned i = 0; inputQueue && i < 4 && xQueueReceive(inputQueue, &input, 0) == pdTRUE; ++i) {
        if (!mavtls::enabled.load() || input.session != activeSession.load()) continue;
        if (input.session != parserSession) { mavlink.ResetGCSParser(MAVLINK_COMM_2); parserSession = input.session; }
        mavlink.ProcessMAVLinkFromGCS(input.data, input.length, MAVLINK_COMM_2);
    }
}
static void SendMavlinkWebSocket(const uint8_t *data, size_t len) {
    using namespace mavtls;
    const uint32_t session = activeSession.load();
    if (!session || !enabled.load() || !outputQueue || len > MAVLINK_MAX_PACKET_LEN) return;
    Output output{}; output.session = session; output.length = len;
    memcpy(output.data, data, len);
    if (xQueueSend(outputQueue, &output, 0) != pdTRUE) closeSession.store(session);
}
