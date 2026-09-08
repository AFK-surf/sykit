#ifndef SYKIT_NODE_AUTH_H
#define SYKIT_NODE_AUTH_H

#include <synch.h>

#define NODE_AUTH_MAX_KEYS 16
#define NODE_AUTH_CONFIG_BYTES 1024

static int node_base32_digit(char c) {
    const char *alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769";
    if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
    for (int i = 0; i < 32; ++i) {
        if (c == alphabet[i]) return i;
    }
    return -1;
}

/* Synchronicity's z-base-32 node IDs, as printed by `synch id`.
 * Accept uppercase as a convenience, but do not guess alternate alphabets.
 * The final four padding bits must be zero; '=' padding is not accepted. */
static int node_decode_key(const char *text, sy_u64 len, sy_u8 out[32]) {
    if (len != 52) return 0;
    sy_u32 accumulator = 0, bits = 0;
    sy_u64 written = 0;
    for (sy_u64 i = 0; i < len; ++i) {
        int digit = node_base32_digit(text[i]);
        if (digit < 0) return 0;
        accumulator = (accumulator << 5) | (sy_u32)digit;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out[written++] = (sy_u8)(accumulator >> bits);
        }
    }
    return written == 32 && (accumulator & 15) == 0;
}

static int node_list_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* A comma-separated list of base32 Iroh device public keys. Configuration
 * belongs to the serving node's activation, never connection metadata.
 * Validate the entire bounded list before granting access, even after a match.
 * Empty entries, malformed keys, hex and truncated lists all fail closed. */
static int node_is_authorized(void) {
    char configured[NODE_AUTH_CONFIG_BYTES];
    sy_s64 length = sy_config_get(SY_STR("allowed_node_key"), configured,
                                 sizeof configured);
    if (length <= 0 || length >= (sy_s64)sizeof configured) return 0;
    sy_u8 allowed[32], peer[32];
    if (sy_peer_device_key(peer) != 32) return 0;
    sy_u64 start = 0, count = 0;
    int matched = 0;
    for (;;) {
        sy_u64 end = start;
        while (end < (sy_u64)length && configured[end] != ',') ++end;
        sy_u64 first = start, last = end;
        while (first < last && node_list_space(configured[first])) ++first;
        while (last > first && node_list_space(configured[last - 1])) --last;
        if (++count > NODE_AUTH_MAX_KEYS ||
            !node_decode_key(configured + first, last - first, allowed))
            return 0;
        if (sy_ct_eq(peer, allowed, sizeof allowed) == 1) matched = 1;
        if (end == (sy_u64)length) return matched;
        start = end + 1;
    }
}

#endif
