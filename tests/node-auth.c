#include <assert.h>
#include <stdio.h>
#include <string.h>
#define memcpy sdk_memcpy
#define memset sdk_memset
#define memmove sdk_memmove
#include "node-auth.h"
#undef memcpy
#undef memset
#undef memmove

static const char *config;
static sy_s64 reported_length;
static sy_s64 peer_result;
static sy_u8 peer_key[32];

sy_s64 sy_config_get(const char *key, sy_u64 key_len, char *out, sy_u64 cap) {
    assert(key_len == strlen("allowed_node_key"));
    assert(memcmp(key, "allowed_node_key", key_len) == 0);
    if (config) {
        sy_u64 n = reported_length > 0 ? (sy_u64)reported_length : 0;
        if (n >= cap) n = cap - 1;
        memcpy(out, config, n);
        out[n] = 0;
    }
    return reported_length;
}
sy_s64 sy_peer_device_key(void *out) {
    if (peer_result < 0) return peer_result;
    memcpy(out, peer_key, 32);
    return 32;
}
sy_s64 sy_ct_eq(const void *a, const void *b, sy_u64 len) {
    return memcmp(a, b, len) == 0;
}

static void check(const char *value, int expected) {
    config = value;
    reported_length = (sy_s64)strlen(value);
    assert(node_is_authorized() == expected);
}

int main(void) {
    /* Fixtures encoded independently with Python's RFC 4648 base64.b32encode. */
    const char *a = "vkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkva";
    const char *b = "xo53xo53xo53xo53xo53xo53xo53xo53xo53xo53xo53xo53xo5q";
    char list[1100], mutated[53];
    memset(peer_key, 0xaa, sizeof peer_key);
    peer_result = 32;
    check(a, 1);
    for (int i = 0; i < 52; ++i) {
        char c = a[i];
        mutated[i] = c >= 'a' && c <= 'z' ? c - 'a' + 'A' : c;
    }
    mutated[52] = 0;
    check(mutated, 1);
    check(b, 0);
    snprintf(list, sizeof list, " %s,\t%s\r\n", b, a);
    check(list, 1);
    snprintf(list, sizeof list, "%s,%s", a, b);
    memset(peer_key, 0xbb, sizeof peer_key);
    check(list, 1); /* the second configured node is independently allowed */
    memset(peer_key, 0xcc, sizeof peer_key);
    check(list, 0);
    memset(peer_key, 0xaa, sizeof peer_key);
    snprintf(list, sizeof list, "%s,invalid", a);
    check(list, 0); /* a match cannot hide malformed later policy */
    snprintf(list, sizeof list, "%s,", a);
    check(list, 0);
    snprintf(list, sizeof list, ",%s", a);
    check(list, 0);
    snprintf(list, sizeof list, "%s,,%s", a, b);
    check(list, 0);
    for (int i = 0; i < 52; ++i) {
        memcpy(mutated, a, 53);
        mutated[i] = '0';
        check(mutated, 0);
    }
    memcpy(mutated, a, 53);
    mutated[51] = 'b'; /* same decoded bytes, nonzero unused bits */
    check(mutated, 0);
    check("", 0);
    check(" \t\n", 0);
    memset(list, 'a', 64);
    list[64] = 0;
    check(list, 0); /* hex is no longer accepted */
    snprintf(list, sizeof list, "%s=", a);
    check(list, 0);
    list[0] = 0;
    for (int i = 0; i < 16; ++i) {
        if (i) strcat(list, ",");
        strcat(list, a);
    }
    check(list, 1);
    strcat(list, ",");
    strcat(list, a);
    check(list, 0);
    memset(list, ' ', sizeof list - 1);
    memcpy(list, a, 52);
    list[sizeof list - 1] = 0;
    check(list, 0); /* snprintf-style truncation */
    memcpy(mutated, a, 53);
    mutated[10] = 0;
    config = mutated;
    reported_length = 52;
    assert(!node_is_authorized());
    config = a;
    reported_length = SY_ENOENT;
    assert(!node_is_authorized());
    peer_result = SY_EPERM;
    check(a, 0);
    return 0;
}
