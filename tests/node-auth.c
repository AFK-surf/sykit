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
    /* Fixtures encoded independently with Python's base32 encoder and the z-base-32 alphabet. */
    const char *a = "ikikikikikikikikikikikikikikikikikikikikikikikikikiy";
    const char *b = "zq75zq75zq75zq75zq75zq75zq75zq75zq75zq75zq75zq75zq7o";
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
    /* Regression: the exact node ID from `synch id`, including 8, 9 and 1. */
    const sy_u8 displayed_key_bytes[32] = {
        0x42, 0x3d, 0xa3, 0xf9, 0x52, 0xf2, 0x84, 0x74,
        0xc3, 0xfe, 0xe4, 0xf9, 0x10, 0x26, 0xda, 0x01,
        0x45, 0xec, 0x31, 0xa4, 0xd0, 0x83, 0x3b, 0x00,
        0x1e, 0xf8, 0x6d, 0xa8, 0x72, 0x5c, 0xe3, 0xfb,
    };
    memcpy(peer_key, displayed_key_bytes, 32);
    check("ee6486k16kn8jo96huhtyjs4yfn6acpr4nbusyy69bs4oh1hhx7o", 1);
    check("EE6486K16KN8JO96HUHTYJS4YFN6ACPR4NBUSYY69BS4OH1HHX7O", 1);
    peer_key[31] ^= 1;
    check("ee6486k16kn8jo96huhtyjs4yfn6acpr4nbusyy69bs4oh1hhx7o", 0);
    memset(peer_key, 0xaa, sizeof peer_key);
    peer_result = SY_EPERM;
    check(a, 0);
    return 0;
}
