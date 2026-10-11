#pragma once

#include <ArduinoJson.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/oid.h>
#include <mbedtls/sha256.h>
#include <mbedtls/platform_util.h>
#include <string>
#include <cstring>
#include <ctime>

namespace mavtls {
constexpr size_t MaxBundle = 8192;
inline bool hostnameValid(const std::string &s) {
    if (s.size() < 7 || s.size() > 69 || s.compare(s.size() - 6, 6, ".local")) return false;
    const size_t n = s.size() - 6;
    for (size_t i = 0; i < n; ++i) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' && i && i + 1 < n))) return false;
    }
    return true;
}
inline bool originValid(const std::string &s) {
    if (s.size() <= 8 || s.size() > 192 || s.compare(0, 8, "https://")) return false;
    const auto colon = s.find(':', 8);
    const size_t end = colon == std::string::npos ? s.size() : colon;
    if (end == 8 || s[8] == '.' || s[end - 1] == '.') return false;
    for (size_t i = 8; i < end; ++i) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.')) return false;
    }
    if (colon != std::string::npos) {
        unsigned port = 0;
        if (s.size() - colon - 1 > 5) return false;
        for (size_t i = colon + 1; i < s.size(); ++i) {
            if (s[i] < '0' || s[i] > '9') return false;
            port = port * 10 + s[i] - '0';
        }
        if (!port || port > 65535) return false;
    }
    return true;
}
inline bool tokenValid(const std::string &s) {
    if (s.size() != 64) return false;
    for (char c : s) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}
inline bool tokenMatches(const char *candidate, const std::string &token) {
    if (!candidate || strlen(candidate) != 64 || token.size() != 64) return false;
    unsigned difference = 0;
    for (size_t i = 0; i < 64; ++i) difference |= uint8_t(candidate[i]) ^ uint8_t(token[i]);
    return difference == 0;
}
struct Credentials {
    std::string hostname, origin, token, certificate, privateKey, fingerprint, expires;
    ~Credentials() {
        if (!privateKey.empty()) mbedtls_platform_zeroize(&privateKey[0], privateKey.size());
        if (!token.empty()) mbedtls_platform_zeroize(&token[0], token.size());
    }
};
inline bool parseCredentials(const char *data, size_t length, Credentials &out, const char *&error) {
    error = "Invalid TLS bundle.";
    if (!length || length > MaxBundle || memchr(data, 0, length)) return false;
    JsonDocument doc;
    if (deserializeJson(doc, data, length) || doc["version"].as<int>() != 1) return false;
    auto stringField = [&](const char *field, std::string &value, size_t max) {
        if (!doc[field].is<const char *>()) return false;
        JsonString s = doc[field].as<JsonString>();
        if (!s.size() || s.size() > max || strlen(s.c_str()) != s.size()) return false;
        value.assign(s.c_str(), s.size()); return true;
    };
    if (!stringField("hostname", out.hostname, 69) || !hostnameValid(out.hostname) ||
        !stringField("origin", out.origin, 192) || !originValid(out.origin) ||
        !stringField("token", out.token, 64) || !tokenValid(out.token) ||
        !stringField("certificate", out.certificate, 4096) ||
        !stringField("private_key", out.privateKey, 2048)) return false;
    mbedtls_x509_crt cert; mbedtls_x509_crt_init(&cert);
    mbedtls_pk_context key; mbedtls_pk_init(&key);
    bool ok = false;
    do {
        error = "Invalid certificate or unencrypted private key.";
        if (mbedtls_x509_crt_parse(&cert, reinterpret_cast<const uint8_t *>(out.certificate.c_str()), out.certificate.size() + 1) ||
            mbedtls_pk_parse_key(&key, reinterpret_cast<const uint8_t *>(out.privateKey.c_str()), out.privateKey.size() + 1, nullptr, 0)) break;
        error = "Certificate and private key do not match.";
        if (mbedtls_pk_check_pair(&cert.pk, &key)) break;
        error = "Use an EC key of at least 256 bits or RSA of at least 2048 bits, signed with SHA-256 or stronger.";
        const bool strongKey = (mbedtls_pk_can_do(&cert.pk, MBEDTLS_PK_RSA) && mbedtls_pk_get_bitlen(&cert.pk) >= 2048) ||
            (mbedtls_pk_can_do(&cert.pk, MBEDTLS_PK_ECKEY) && mbedtls_pk_get_bitlen(&cert.pk) >= 256);
        if (!strongKey || (cert.sig_md != MBEDTLS_MD_SHA256 && cert.sig_md != MBEDTLS_MD_SHA384 && cert.sig_md != MBEDTLS_MD_SHA512)) break;
        error = "Certificate must be a TLS server leaf with digitalSignature and serverAuth extensions.";
        if (cert.ca_istrue || !(cert.ext_types & MBEDTLS_X509_EXT_KEY_USAGE) ||
            !(cert.ext_types & MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE) ||
            mbedtls_x509_crt_check_key_usage(&cert, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) ||
            mbedtls_x509_crt_check_extended_key_usage(&cert, MBEDTLS_OID_SERVER_AUTH, MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH))) break;
        bool matches = false;
        for (auto *san = &cert.subject_alt_names; san && san->buf.p; san = san->next) {
            if ((san->buf.tag & 0x1f) == MBEDTLS_X509_SAN_DNS_NAME && san->buf.len == out.hostname.size() &&
                !memcmp(san->buf.p, out.hostname.data(), san->buf.len)) matches = true;
        }
        error = "Certificate SAN must contain the exact configured .local hostname.";
        if (!matches) break;
        // Offline AP mode has no trusted wall clock. Clients always enforce validity.
        error = "Certificate is expired or not yet valid.";
        if (time(nullptr) > 1577836800 && (mbedtls_x509_time_is_past(&cert.valid_to) || mbedtls_x509_time_is_future(&cert.valid_from))) break;
        uint8_t hash[32];
        if (mbedtls_sha256_ret(cert.raw.p, cert.raw.len, hash, 0)) break;
        static const char hex[] = "0123456789abcdef";
        out.fingerprint.clear();
        for (auto byte : hash) { out.fingerprint += hex[byte >> 4]; out.fingerprint += hex[byte & 15]; }
        char expiry[16]; snprintf(expiry, sizeof(expiry), "%04d-%02d-%02d", cert.valid_to.year, cert.valid_to.mon, cert.valid_to.day);
        out.expires = expiry; ok = true; error = nullptr;
    } while (false);
    mbedtls_pk_free(&key); mbedtls_x509_crt_free(&cert);
    return ok;
}
} // namespace mavtls
