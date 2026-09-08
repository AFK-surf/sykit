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

struct node_identity {
    sy_u8 key[32];
    char origin[318]; /* 63-byte member + '@' + 253-byte domain + NUL */
    sy_s64 origin_len;
};

/* -1 is malformed, 0 is a valid nonmatch, 1 matches authenticated identity. */
static int node_match_entry(char *text, sy_u64 len, const struct node_identity *peer) {
    int named = 0;
    for (sy_u64 i = 0; i < len; ++i) {
        if (text[i] == '@') named = 1;
    }
    if (named) {
        sy_s64 normalized = node_normalize_origin(text, len);
        if (normalized < 0) return -1;
        return normalized == peer->origin_len &&
            sy_ct_eq(peer->origin, text, (sy_u64)normalized) == 1;
    }
    sy_u8 key[32];
    if (!node_decode_key(text, len, key)) return -1;
    return sy_ct_eq(peer->key, key, sizeof key) == 1;
}

static int node_inline_matches(char *configured, sy_u64 length,
                               const struct node_identity *peer) {
    sy_u64 start = 0, count = 0;
    int matched = 0;
    for (;;) {
        sy_u64 end = start;
        while (end < length && configured[end] != ',') ++end;
        sy_u64 first = start, last = end;
        while (first < last && node_list_space(configured[first])) ++first;
        while (last > first && node_list_space(configured[last - 1])) --last;
        if (++count > NODE_AUTH_MAX_PEERS) return 0;
        int result = node_match_entry(configured + first, last - first, peer);
        if (result < 0) return 0;
        if (result == 1) matched = 1;
        if (end == length) return matched;
        start = end + 1;
    }
}

#define NODE_AUTH_FILE_BYTES 65536
#define NODE_AUTH_FILE_PEERS 1024
#define NODE_AUTH_LINE_BYTES 1023
#define NODE_AUTH_READ_MS 10000

/* Empty lines are ignored; every nonempty line must be one valid peer. */
static int node_file_line(char *line, sy_u64 len, const struct node_identity *peer,
                          sy_u64 *count, int *matched) {
    sy_u64 first = 0;
    while (first < len && node_list_space(line[first])) ++first;
    while (len > first && node_list_space(line[len - 1])) --len;
    if (first == len) return 1;
    if (++*count > NODE_AUTH_FILE_PEERS) return 0;
    int result = node_match_entry(line + first, len - first, peer);
    if (result < 0) return 0;
    if (result == 1) *matched = 1;
    return 1;
}

/* sy_open pins the selected object root. Read its complete advertised size
 * before granting access, so neither an early match nor premature EOF can
 * conceal malformed policy. Memory usage stays bounded independently of size. */
static int node_file_matches(sy_s64 object, const struct node_identity *peer) {
    sy_s64 stat = sy_stat(object);
    if (stat < 0) return 0;
    sy_s64 size = 0;
    char kind[8];
    sy_s64 kind_len = sy_json_get_string(stat, SY_STR("kind"), kind, sizeof kind);
    sy_s64 size_result = sy_json_get_i64(stat, SY_STR("size"), &size);
    sy_close(stat);
    if (kind_len != 4 || sy_ct_eq(kind, "file", 4) != 1 || size_result < 0 ||
        size <= 0 || size > NODE_AUTH_FILE_BYTES) return 0;

    char chunk[1024], line[NODE_AUTH_LINE_BYTES];
    sy_u64 offset = 0, used = 0, count = 0;
    int matched = 0;
    sy_u64 started = sy_monotonic_ns();
    while (offset < (sy_u64)size) {
        sy_u64 elapsed = (sy_monotonic_ns() - started) / 1000000;
        if (elapsed >= NODE_AUTH_READ_MS) return 0;
        sy_u64 want = (sy_u64)size - offset;
        if (want > sizeof chunk) want = sizeof chunk;
        sy_s64 got = sy_pread(object, chunk, want, offset);
        if (got == SY_EAGAIN) {
            struct sy_pollfd wait = {object, SY_POLL_IN, 0};
            if (sy_poll(&wait, 1, (sy_s64)(NODE_AUTH_READ_MS - elapsed)) <= 0 ||
                (wait.revents & (SY_POLL_ERR | SY_POLL_HUP))) return 0;
            continue;
        }
        if (got <= 0 || (sy_u64)got > want) return 0;
        for (sy_u64 i = 0; i < (sy_u64)got; ++i) {
            if (chunk[i] == '\n') {
                if (!node_file_line(line, used, peer, &count, &matched)) return 0;
                used = 0;
            } else {
                if (used == sizeof line) return 0;
                line[used++] = chunk[i];
            }
        }
        offset += (sy_u64)got;
    }
    if (!node_file_line(line, used, peer, &count, &matched)) return 0;
    return matched;
}

/* Exactly one operator-controlled source: inline peers or a tree allowlist.
 * No connection metadata and no fallback from a failed file read. */
static int node_is_authorized(void) {
    char configured[NODE_AUTH_CONFIG_BYTES], path[NODE_AUTH_CONFIG_BYTES];
    sy_s64 length = sy_config_get(SY_STR("allowed_peers"), configured,
                                 sizeof configured);
    sy_s64 path_len = sy_config_get(SY_STR("allowlist"), path, sizeof path);
    int from_file = path_len != SY_ENOENT;
    if (from_file) {
        if (length != SY_ENOENT || path_len <= 0 || path_len >= (sy_s64)sizeof path)
            return 0;
        for (sy_s64 i = 0; i < path_len; ++i) {
            if (path[i] == 0) return 0;
        }
    } else if (length <= 0 || length >= (sy_s64)sizeof configured) {
        return 0;
    }
    struct node_identity peer;
    if (sy_peer_device_key(peer.key) != 32) return 0;
    peer.origin_len = sy_peer_origin(peer.origin, sizeof peer.origin);
    if (peer.origin_len < 0 || peer.origin_len >= (sy_s64)sizeof peer.origin) return 0;
    if (!from_file) return node_inline_matches(configured, (sy_u64)length, &peer);
    sy_s64 object = sy_open(path, (sy_u64)path_len);
    if (object < 0) return 0;
    int matched = node_file_matches(object, &peer);
    sy_close(object);
    return matched;
}

#endif
