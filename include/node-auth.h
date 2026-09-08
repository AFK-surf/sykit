#ifndef SYKIT_NODE_AUTH_H
#define SYKIT_NODE_AUTH_H

#include <synch.h>

static int node_hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Exactly one raw Iroh device public key, encoded as 64 hex characters.
 * Config belongs to the serving node's activation, never connection metadata.
 * Missing, truncated, malformed and mismatched keys all fail closed. */
static int node_is_authorized(void) {
    char configured[65];
    sy_u8 allowed[32], peer[32];
    if (sy_config_get(SY_STR("allowed_node_key"), configured,
                      sizeof configured) != 64)
        return 0;
    for (sy_u64 i = 0; i < sizeof allowed; ++i) {
        int hi = node_hex_digit(configured[2 * i]);
        int lo = node_hex_digit(configured[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        allowed[i] = (sy_u8)((hi << 4) | lo);
    }
    if (sy_peer_device_key(peer) < 0) return 0;
    return sy_ct_eq(peer, allowed, sizeof allowed) == 1;
}

#endif
