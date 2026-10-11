#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <cassert>
class String : public std::string {
public:
    using std::string::string;
    String(const std::string &s) : std::string(s) {}
};
namespace AsyncWebRequestMethod { enum Method { HTTP_GET, HTTP_POST, HTTP_DELETE }; }
using namespace AsyncWebRequestMethod;
struct AsyncResponseStream {
    std::string body;
    void addHeader(const char *, const char *) {}
    size_t write(uint8_t c) { body += char(c); return 1; }
    size_t write(const uint8_t *p, size_t n) { body.append(reinterpret_cast<const char *>(p), n); return n; }
};
struct Header { String text; String value() const { return text; } };
struct AsyncWebServerRequest {
    int code = 0;
    std::string body;
    std::map<std::string, Header> headers;
    std::map<std::string, bool> attributes;
    std::function<void()> onClose;
    bool hasHeader(const char *key) const { return headers.count(key); }
    Header *getHeader(const char *key) { return &headers[key]; }
    String host() const { return "10.0.0.1"; }
    bool hasAttribute(const char *key) { return attributes.count(key); }
    void setAttribute(const char *key, bool value) { attributes[key] = value; }
    void onDisconnect(std::function<void()> f) { onClose = f; }
    void disconnect() { if (onClose) onClose(); }
    void send(int c, const char *, const char *message) { code = c; body = message; }
    void send(AsyncResponseStream *s) { code = 200; body = s->body; delete s; }
    AsyncResponseStream *beginResponseStream(const char *) { return new AsyncResponseStream; }
};
struct AsyncWebServer { template<class... T> void on(T...) {} };
constexpr int MAVLINK_MAX_PACKET_LEN = 280, MAVLINK_COMM_2 = 2;
struct TestMavlink {
    unsigned resets = 0;
    std::vector<uint8_t> input;
    void ResetGCSParser(int channel) { assert(channel == 2); ++resets; }
    void ProcessMAVLinkFromGCS(uint8_t *p, uint16_t n, int channel) {
        assert(channel == 2); input.insert(input.end(), p, p + n);
    }
};
static TestMavlink mavlink;
