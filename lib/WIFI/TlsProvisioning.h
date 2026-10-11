#pragma once
#include "TlsCredentials.h"
#include <nvs.h>
#include <atomic>
#include <memory>

namespace mavtls {
static std::unique_ptr<Credentials> credentials;
static std::string mdnsLabel;
static const char *startupError = nullptr;
static std::atomic<bool> serverRunning{false}, provisioningAllowed{false}, restartNeeded{false}, rebootRequested{false};
static const char UploadError[] = "tls-upload-error", UploadDone[] = "tls-upload-done";
static AsyncWebServerRequest *uploadOwner = nullptr;
static std::unique_ptr<char[]> uploadBuffer;
static size_t uploadLength = 0;

static bool store(const char *data, size_t length) {
    nvs_handle_t handle;
    if (nvs_open("mavtls", NVS_READWRITE, &handle) != ESP_OK) return false;
    esp_err_t result = data ? nvs_set_blob(handle, "config", data, length) : nvs_erase_key(handle, "config");
    if (!data && result == ESP_ERR_NVS_NOT_FOUND) result = ESP_OK;
    if (result == ESP_OK) result = nvs_commit(handle);
    nvs_close(handle);
    return result == ESP_OK;
}
static void load() {
    nvs_handle_t handle;
    if (nvs_open("mavtls", NVS_READONLY, &handle) != ESP_OK) return;
    size_t length = 0;
    if (nvs_get_blob(handle, "config", nullptr, &length) == ESP_OK && length && length <= MaxBundle) {
        std::unique_ptr<char[]> buffer(new (std::nothrow) char[length]);
        std::unique_ptr<Credentials> parsed(new (std::nothrow) Credentials);
        if (buffer && parsed && nvs_get_blob(handle, "config", buffer.get(), &length) == ESP_OK &&
            parseCredentials(buffer.get(), length, *parsed, startupError)) {
            credentials = std::move(parsed);
            mdnsLabel = credentials->hostname.substr(0, credentials->hostname.size() - 6);
        }
        if (buffer) mbedtls_platform_zeroize(buffer.get(), length);
    }
    nvs_close(handle);
}
static bool mayProvision(AsyncWebServerRequest *request) {
    if (!provisioningAllowed.load() || restartNeeded.load()) return false;
    // Local HTTP bootstrap is restricted to AP firmware-update mode.
    return !request->hasHeader("Origin") ||
        request->getHeader("Origin")->value() == String("http://") + request->host();
}
static void discardUpload() {
    if (uploadBuffer) mbedtls_platform_zeroize(uploadBuffer.get(), MaxBundle);
    uploadBuffer.reset(); uploadOwner = nullptr; uploadLength = 0;
}
static void upload(AsyncWebServerRequest *request, const String &, size_t index, uint8_t *data, size_t len, bool final) {
    if (request->hasAttribute(UploadError)) return;
    if (!mayProvision(request)) { request->setAttribute(UploadError, true); return; }
    if (!index) {
        if (uploadOwner || request->hasAttribute(UploadDone)) { request->setAttribute(UploadError, true); return; }
        uploadBuffer.reset(new (std::nothrow) char[MaxBundle]);
        if (!uploadBuffer) { request->setAttribute(UploadError, true); return; }
        uploadOwner = request; uploadLength = 0;
        request->onDisconnect([request]() { if (uploadOwner == request) discardUpload(); });
    }
    if (uploadOwner != request || index != uploadLength || len > MaxBundle - uploadLength) {
        request->setAttribute(UploadError, true); return;
    }
    memcpy(uploadBuffer.get() + uploadLength, data, len); uploadLength += len;
    if (final) request->setAttribute(UploadDone, true);
}
static void uploaded(AsyncWebServerRequest *request) {
    const bool owner = uploadOwner == request;
    const char *error = "Upload one TLS JSON bundle (maximum 8192 bytes) in AP firmware-update mode.";
    int code = 400;
    if (owner && mayProvision(request) && !request->hasAttribute(UploadError) && request->hasAttribute(UploadDone)) {
        Credentials parsed;
        if (parseCredentials(uploadBuffer.get(), uploadLength, parsed, error)) {
            if (store(uploadBuffer.get(), uploadLength)) {
                restartNeeded.store(true); code = 200;
                error = "TLS settings saved. Restart the Backpack to activate them.";
            } else { code = 500; error = "Unable to save TLS settings in NVS. Existing running settings remain active."; }
        }
    }
    if (owner) discardUpload();
    request->send(code, "text/plain", error);
}
static void status(AsyncWebServerRequest *request) {
    JsonDocument doc;
    doc["configured"] = bool(credentials);
    doc["running"] = serverRunning.load();
    doc["can_provision"] = provisioningAllowed.load() && !restartNeeded.load();
    doc["restart_needed"] = restartNeeded.load();
    if (credentials) {
        doc["hostname"] = credentials->hostname;
        doc["origin"] = credentials->origin;
        doc["expires"] = credentials->expires;
        doc["fingerprint"] = credentials->fingerprint;
    }
    if (startupError) doc["error"] = startupError;
    auto *response = request->beginResponseStream("application/json");
    response->addHeader("Cache-Control", "no-store");
    serializeJson(doc, *response); request->send(response);
}
static void setupProvisioning(AsyncWebServer &server) {
    load();
    server.on("/tls/status", HTTP_GET, status);
    server.on("/tls/credentials", HTTP_POST, uploaded, upload);
    server.on("/tls/credentials", HTTP_DELETE, [](AsyncWebServerRequest *request) {
        if (!mayProvision(request) || uploadOwner) { request->send(409, "text/plain", "Use AP firmware-update mode with no upload in progress."); return; }
        if (!store(nullptr, 0)) { request->send(500, "text/plain", "Unable to clear TLS settings."); return; }
        restartNeeded.store(true);
        request->send(200, "text/plain", "TLS settings cleared. Restart to apply.");
    });
    server.on("/tls/restart", HTTP_POST, [](AsyncWebServerRequest *request) {
        const bool sameOrigin = !request->hasHeader("Origin") || request->getHeader("Origin")->value() == String("http://") + request->host();
        if (!sameOrigin || !provisioningAllowed.load() || !restartNeeded.load() || uploadOwner) {
            request->send(409, "text/plain", "Restart is available after provisioning, in AP firmware-update mode."); return;
        }
        request->send(200, "text/plain", "Restarting. Reconnect to the Backpack Wi-Fi afterward.");
        rebootRequested.store(true);
    });
}
} // namespace mavtls
