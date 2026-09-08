#include <assert.h>
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

int main(void) {
    char key[66];
    memset(key, 'a', 64);
    key[64] = 0;
    memset(peer_key, 0xaa, sizeof peer_key);
    config = key;
    reported_length = 64;
    assert(node_is_authorized());
    memset(key, 'A', 64);
    assert(node_is_authorized());
    peer_key[31] ^= 1;
    assert(!node_is_authorized());
    peer_key[31] ^= 1;
    peer_result = SY_EPERM;
    assert(!node_is_authorized());
    peer_result = 32;
    for (int i = 0; i < 64; ++i) {
        key[i] = 'g';
        assert(!node_is_authorized());
        key[i] = 'A';
    }
    key[10] = 0;
    assert(!node_is_authorized());
    key[10] = 'A';
    const sy_s64 lengths[] = {SY_ENOENT, 0, 1, 63, 65, 4096};
    for (unsigned i = 0; i < sizeof lengths / sizeof lengths[0]; ++i) {
        reported_length = lengths[i];
        assert(!node_is_authorized());
    }
    return 0;
}
