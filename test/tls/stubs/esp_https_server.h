#pragma once
#include "HttpMocks.h"
#include "nvs.h"
using httpd_handle_t = void *;
enum http_method { HTTP_GET, HTTP_POST, HTTP_OPTIONS };
enum httpd_ws_type_t { HTTPD_WS_TYPE_CONTINUE, HTTPD_WS_TYPE_TEXT, HTTPD_WS_TYPE_BINARY,
                      HTTPD_WS_TYPE_CLOSE = 8, HTTPD_WS_TYPE_PING, HTTPD_WS_TYPE_PONG };
struct httpd_ws_frame_t { bool final = true; bool fragmented = false; httpd_ws_type_t type; uint8_t *payload; size_t len; };
struct httpd_req_t {
    http_method method = http_method::HTTP_GET;
    void *sess_ctx = nullptr;
    void (*free_ctx)(void *) = nullptr;
    int fd = 4, reads = 0;
    std::string origin, query;
    httpd_ws_frame_t incoming{};
};
struct httpd_uri_t {
    const char *uri = nullptr;
    http_method method{};
    esp_err_t (*handler)(httpd_req_t *) = nullptr;
    bool is_websocket = false, handle_ws_control_frames = false;
};
struct httpd_ssl_config_t {
    struct { int max_open_sockets, recv_wait_timeout, send_wait_timeout; bool lru_purge_enable; } httpd;
    const uint8_t *cacert_pem, *prvtkey_pem;
    size_t cacert_len, prvtkey_len;
};
#define HTTPD_SSL_CONFIG_DEFAULT() {}
static int testCloseRequests = 0, testCloseCode = 0;
static bool testSendFail = false;
static std::vector<uint8_t> testDownlink;
static std::vector<httpd_uri_t> testRoutes;
inline int httpd_ssl_start(httpd_handle_t *h, httpd_ssl_config_t *c) {
    assert(c->cacert_pem && c->prvtkey_pem); *h = reinterpret_cast<void *>(1); return ESP_OK;
}
inline void httpd_ssl_stop(httpd_handle_t) {}
inline int httpd_register_uri_handler(httpd_handle_t, const httpd_uri_t *r) { testRoutes.push_back(*r); return ESP_OK; }
inline int httpd_req_to_sockfd(httpd_req_t *r) { return r->fd; }
inline int copyText(const std::string &s, char *out, size_t n) {
    if (s.size() >= n || s.empty()) return ESP_FAIL;
    memcpy(out, s.c_str(), s.size() + 1); return ESP_OK;
}
inline int httpd_req_get_hdr_value_str(httpd_req_t *r, const char *, char *out, size_t n) { return copyText(r->origin, out, n); }
inline int httpd_req_get_url_query_str(httpd_req_t *r, char *out, size_t n) { return copyText(r->query, out, n); }
inline int httpd_query_key_value(const char *q, const char *, char *out, size_t n) {
    return strncmp(q, "token=", 6) ? ESP_FAIL : copyText(q + 6, out, n);
}
inline int httpd_ws_recv_frame(httpd_req_t *r, httpd_ws_frame_t *frame, size_t max) {
    ++r->reads;
    if (!max) { *frame = r->incoming; return ESP_OK; }
    assert(r->incoming.len && max >= r->incoming.len);
    memcpy(frame->payload, r->incoming.payload, r->incoming.len); return ESP_OK;
}
inline int httpd_ws_send_frame_async(httpd_handle_t, int, httpd_ws_frame_t *f) {
    if (testSendFail) return ESP_FAIL;
    if (f->type == HTTPD_WS_TYPE_BINARY) testDownlink.insert(testDownlink.end(), f->payload, f->payload + f->len);
    if (f->type == HTTPD_WS_TYPE_CLOSE) testCloseCode = (unsigned(f->payload[0]) << 8) | f->payload[1];
    return ESP_OK;
}
inline int httpd_ws_send_frame(httpd_req_t *r, httpd_ws_frame_t *f) { return httpd_ws_send_frame_async(nullptr, r->fd, f); }
inline int httpd_sess_trigger_close(httpd_handle_t, int) { ++testCloseRequests; return ESP_OK; }
inline int httpd_queue_work(httpd_handle_t, void (*f)(void *), void *arg) { f(arg); return ESP_OK; }
inline int httpd_resp_set_type(httpd_req_t *, const char *) { return ESP_OK; }
inline int httpd_resp_set_hdr(httpd_req_t *, const char *, const char *) { return ESP_OK; }
inline int httpd_resp_sendstr(httpd_req_t *, const char *) { return ESP_OK; }
