#include "TlsCredentials.h"
#include "TlsWebSocketCore.h"
#include <cassert>
#include <fstream>
#include <iterator>
#include <cstdio>

static std::string read(const char *path) {
    std::ifstream file(path); return {std::istreambuf_iterator<char>(file), {}};
}
static bool valid(const std::string &text) {
    mavtls::Credentials credentials; const char *error = nullptr;
    bool result = mavtls::parseCredentials(text.data(), text.size(), credentials, error);
    assert(result == (error == nullptr)); return result;
}
int main(int argc, char **argv) {
    assert(argc == 3);
    const auto bundle = read(argv[1]), other = read(argv[2]);
    assert(valid(bundle));
    mavtls::Credentials credentials; const char *error = nullptr;
    assert(mavtls::parseCredentials(bundle.data(), bundle.size(), credentials, error));
    assert(credentials.fingerprint.size() == 64 && credentials.expires.size() == 10);
    assert(mavtls::tokenMatches(credentials.token.c_str(), credentials.token));
    assert(!mavtls::tokenMatches("", credentials.token));
    auto wrong = credentials.token; wrong[0] = wrong[0] == 'a' ? 'b' : 'a';
    assert(!mavtls::tokenMatches(wrong.c_str(), credentials.token));
    for (int mutation = 0; mutation < 10; ++mutation) {
        JsonDocument doc; assert(!deserializeJson(doc, bundle));
        switch (mutation) {
        case 0: doc["version"] = 2; break;
        case 1: doc["hostname"] = "other.local"; break;
        case 2: doc["hostname"] = "elrs_txbp.local"; break;
        case 3: doc["origin"] = "http://gcs.loftedaero.com"; break;
        case 4: doc["origin"] = "https://gcs.loftedaero.com/path"; break;
        case 5: doc["origin"] = "https://gcs.loftedaero.com:99999"; break;
        case 6: doc["token"] = "short"; break;
        case 7: { JsonDocument alt; deserializeJson(alt, other); doc["private_key"] = alt["private_key"]; break; }
        case 8: doc["certificate"] = "not a certificate"; break;
        case 9: doc["hostname"] = std::string("ok.local\0evil", 13); break;
        }
        std::string text; serializeJson(doc, text); assert(!valid(text));
    }
    assert(!valid(std::string(8193, 'x')) && !valid("{}"));
    assert(!mavtls::hostnameValid("-bad.local") && !mavtls::hostnameValid("bad-.local"));
    assert(!mavtls::originValid("https://user@host") && !mavtls::originValid("https://host:0"));
    assert(mavtls::originValid("https://localhost:8443"));
    mavtls::Message message;
    uint8_t bytes[1024]{};
    assert(message.accept(2, false, bytes, 700) == 0);
    assert(message.accept(0, true, bytes, 324) == 1 && message.length == 1024);
    assert(message.accept(2, true, bytes, 0) == 1 && message.length == 0);
    assert(message.accept(1, true, bytes, 1) == 1003);
    assert(message.accept(0, true, bytes, 1) == 1002);
    message.reset(); assert(message.accept(2, false, bytes, 700) == 0);
    assert(message.accept(0, true, bytes, 325) == 1009);
    message.reset(); assert(message.accept(2, false, bytes, 10) == 0);
    assert(message.accept(2, true, bytes, 10) == 1002);
    puts("Real mbedTLS credentials, authorization and fragmentation tests passed");
}
