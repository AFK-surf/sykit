/* Adapted from Synchronicity; see UPSTREAM.md and README.md.
 * Reports authenticated caller identity. Caller-supplied metadata is omitted
 * so it cannot inject lines that look like trusted identity fields. */
#include <synch.h>

#define TIMEOUT 10000
SY_MANIFEST("{\"manifest\":1,\"name\":\"whoami\",\"max_streams\":8}");

static sy_s64 field(const char *label, const char *value, sy_s64 len,
                    sy_u64 capacity) {
    if (len < 0 || (sy_u64)len >= capacity) return SY_EINVAL;
    sy_s64 result = sy_write_all(SY_SELF, label, sy_strlen(label), TIMEOUT);
    if (result < 0) return result;
    result = sy_write_all(SY_SELF, value, (sy_u64)len, TIMEOUT);
    if (result < 0) return result;
    return sy_write_all(SY_SELF, SY_STR("\n"), TIMEOUT);
}

SY_ENTRY sy_s64 entry(void) {
    char origin[256], hex[65];
    sy_u8 key[32];
    sy_s64 len = sy_peer_origin(origin, sizeof origin);
    if (field("peer-origin: ", origin, len, sizeof origin) < 0) return 1;
    if (sy_peer_device_key(key) < 0) return 1;
    len = sy_hex_encode(key, sizeof key, hex, sizeof hex, 0);
    if (len != 64 || field("peer-key: ", hex, len, sizeof hex) < 0) return 1;
    sy_s64 info = sy_peer_info();
    if (info < 0) return 1;
    char kind[16];
    len = sy_json_get_string(info, SY_STR("kind"), kind, sizeof kind);
    sy_close(info);
    if (field("peer-kind: ", kind, len, sizeof kind) < 0) return 1;
    /* Release both directions immediately; the runtime drains queued text.
       Do not wait for the caller to send input or close its write half. */
    sy_close(SY_SELF);
    return 0;
}
