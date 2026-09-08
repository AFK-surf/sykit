#ifndef SYKIT_NODE_AUTH_H
#define SYKIT_NODE_AUTH_H

#include <synch.h>

#define NODE_AUTH_MAX_PEERS 16
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

/* Normalize named origins with the same ASCII label rules as Synchronicity:
 * lowercase, strip trailing domain dots, 63-byte member/labels, 253-byte domain.
 * Return the canonical byte length, or -1 for a malformed origin. */
static sy_s64 node_normalize_origin(char *text, sy_u64 len) {
    sy_u64 at = 0;
    for (sy_u64 i = 0; i < len; ++i) {
        if (text[i] >= 'A' && text[i] <= 'Z') text[i] += 'a' - 'A';
    }
    while (at < len && text[at] != '@') {
        char c = text[at];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return -1;
        ++at;
    }
    if (at == 0 || at > 63 || at == len) return -1;
    while (len > at + 1 && text[len - 1] == '.') --len;
    if (len <= at + 1 || len - at - 1 > 253) return -1;
    sy_u64 label = at + 1;
    for (sy_u64 i = label; i <= len; ++i) {
        if (i == len || text[i] == '.') {
            if (i == label || i - label > 63 || text[label] == '-' || text[i - 1] == '-')
                return -1;
            label = i + 1;
        } else {
            char c = text[i];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
                return -1;
        }
    }
    return (sy_s64)len;
}

/* Comma-separated z-base-32 public keys and named origins. Configuration
 * belongs to the serving node's activation, never connection metadata.
 * Validate the entire bounded list before granting access, even after a match.
 * Empty entries, malformed peers, hex and truncated lists all fail closed. */
static int node_is_authorized(void) {
    char configured[NODE_AUTH_CONFIG_BYTES];
    sy_s64 length = sy_config_get(SY_STR("allowed_peers"), configured,
                                 sizeof configured);
    if (length <= 0 || length >= (sy_s64)sizeof configured) return 0;
    sy_u8 allowed[32], peer[32];
    if (sy_peer_device_key(peer) != 32) return 0;
    char origin[318]; /* 63-byte member + '@' + 253-byte domain + NUL */
    sy_s64 origin_len = sy_peer_origin(origin, sizeof origin);
    if (origin_len < 0 || origin_len >= (sy_s64)sizeof origin) return 0;
    sy_u64 start = 0, count = 0;
    int matched = 0;
    for (;;) {
        sy_u64 end = start;
        while (end < (sy_u64)length && configured[end] != ',') ++end;
        sy_u64 first = start, last = end;
        while (first < last && node_list_space(configured[first])) ++first;
        while (last > first && node_list_space(configured[last - 1])) --last;
        if (++count > NODE_AUTH_MAX_PEERS) return 0;
        int named = 0;
        for (sy_u64 i = first; i < last; ++i) {
            if (configured[i] == '@') named = 1;
        }
        if (named) {
            sy_s64 len = node_normalize_origin(configured + first, last - first);
            if (len < 0) return 0;
            if (len == origin_len &&
                sy_ct_eq(origin, configured + first, (sy_u64)len) == 1)
                matched = 1;
        } else {
            if (!node_decode_key(configured + first, last - first, allowed)) return 0;
            if (sy_ct_eq(peer, allowed, sizeof allowed) == 1) matched = 1;
        }
        if (end == (sy_u64)length) return matched;
        start = end + 1;
    }
}

#endif
