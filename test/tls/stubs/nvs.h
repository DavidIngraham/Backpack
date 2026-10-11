#pragma once
#include <string>
#include <cstring>
using nvs_handle_t = int;
using esp_err_t = int;
constexpr int ESP_OK = 0, ESP_FAIL = -1, ESP_ERR_NVS_NOT_FOUND = 1, NVS_READONLY = 0, NVS_READWRITE = 1;
static std::string testNvsBlob, testNvsPending;
static bool testNvsFail = false;
inline int nvs_open(const char *, int, nvs_handle_t *out) { *out = 1; return ESP_OK; }
inline void nvs_close(nvs_handle_t) {}
inline int nvs_set_blob(nvs_handle_t, const char *, const void *p, size_t n) {
    if (testNvsFail) return ESP_FAIL;
    testNvsPending.assign(static_cast<const char *>(p), n); return ESP_OK;
}
inline int nvs_commit(nvs_handle_t) { testNvsBlob = testNvsPending; return ESP_OK; }
inline int nvs_erase_key(nvs_handle_t, const char *) { testNvsPending.clear(); return ESP_OK; }
inline int nvs_get_blob(nvs_handle_t, const char *, void *p, size_t *n) {
    if (testNvsBlob.empty()) return ESP_ERR_NVS_NOT_FOUND;
    if (!p) { *n = testNvsBlob.size(); return ESP_OK; }
    if (*n < testNvsBlob.size()) return ESP_FAIL;
    memcpy(p, testNvsBlob.data(), testNvsBlob.size()); *n = testNvsBlob.size(); return ESP_OK;
}
