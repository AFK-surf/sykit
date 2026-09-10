#include <assert.h>
#include <stdio.h>
#include <string.h>
#undef memcpy
#undef memset
#undef memmove
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
static const char *peer_origin = "laptop@cluster.example";
static const char *list_path;
static const char *file_body;
static sy_s64 advertised_size;
static sy_u64 read_chunk = 17, fake_ns, poll_advance_ns;
static int pending_read, poll_count, open_count, object_closes, stat_closes;
static int open_error, stat_error, read_error, poll_timeout;
static const char *file_kind = "file";

sy_s64 sy_config_get(const char *key, sy_u64 key_len, char *out, sy_u64 cap) {
    if (key_len == strlen("allowlist") && memcmp(key, "allowlist", key_len) == 0) {
        return list_path ? snprintf(out, (size_t)cap, "%s", list_path) : SY_ENOENT;
    }
    assert(key_len == strlen("allowed_peers"));
    assert(memcmp(key, "allowed_peers", key_len) == 0);
    if (config) {
        sy_u64 n = reported_length > 0 ? (sy_u64)reported_length : 0;
        if (n >= cap) n = cap - 1;
        memcpy(out, config, n);
        out[n] = 0;
    }
    return reported_length;
}
sy_s64 sy_peer_origin(char *out, sy_u64 capacity) {
    return snprintf(out, (size_t)capacity, "%s", peer_origin);
}
sy_s64 sy_peer_device_key(void *out) {
    if (peer_result < 0) return peer_result;
    memcpy(out, peer_key, 32);
    return 32;
}
sy_s64 sy_ct_eq(const void *a, const void *b, sy_u64 len) {
    return memcmp(a, b, len) == 0;
}

sy_s64 sy_open(const char *path, sy_u64 length) {
    ++open_count;
    assert(length == strlen("code/allowlist.txt"));
    assert(memcmp(path, "code/allowlist.txt", length) == 0);
    return open_error ? SY_ENOENT : 42;
}
sy_s64 sy_stat(sy_s64 object) {
    assert(object == 42);
    return stat_error ? SY_EINVAL : 43;
}
sy_s64 sy_json_get(sy_s64 handle, const char *key, sy_u64 length) {
    assert(handle == 43 && length == 4);
    if (memcmp(key, "size", 4) == 0) return 44;
    assert(memcmp(key, "kind", 4) == 0);
    return 45;
}
sy_s64 sy_json_read_i64(sy_s64 handle, void *out, sy_u64 capacity) {
    assert(handle == 44 && capacity == sizeof advertised_size);
    memcpy(out, &advertised_size, capacity);
    return 0;
}
sy_s64 sy_json_read_string(sy_s64 handle, char *out, sy_u64 cap) {
    assert(handle == 45);
    return snprintf(out, (size_t)cap, "%s", file_kind);
}
sy_s64 sy_close(sy_s64 handle) {
    if (handle == 42) ++object_closes;
    else if (handle == 43) ++stat_closes;
    else assert(handle == 44 || handle == 45);
    return 0;
}
sy_u64 sy_monotonic_ns(void) { return fake_ns; }
sy_s64 sy_poll(struct sy_pollfd *fds, sy_u64 count, sy_s64 timeout) {
    assert(count == 1 && fds[0].handle == 42 && timeout > 0 && timeout <= 10000);
    ++poll_count;
    fake_ns += poll_advance_ns;
    fds[0].revents = SY_POLL_IN;
    return poll_timeout ? 0 : 1;
}
sy_s64 sy_pread(sy_s64 object, void *out, sy_u64 capacity, sy_u64 offset) {
    assert(object == 42);
    if (!pending_read) { pending_read = 1; return SY_EAGAIN; }
    pending_read = 0;
    if (read_error) return SY_EINVAL;
    sy_u64 size = strlen(file_body);
    if (offset >= size) return 0;
    sy_u64 amount = size - offset;
    if (amount > capacity) amount = capacity;
    if (amount > read_chunk) amount = read_chunk;
    memcpy(out, file_body + offset, amount);
    return (sy_s64)amount;
}

static void prepare_file(const char *body) {
    config = NULL;
    reported_length = SY_ENOENT;
    list_path = "code/allowlist.txt";
    file_body = body;
    advertised_size = (sy_s64)strlen(body);
    file_kind = "file";
    pending_read = poll_count = open_count = object_closes = stat_closes = 0;
    fake_ns = poll_advance_ns = 0;
    open_error = stat_error = read_error = poll_timeout = 0;
}
static void check_file(const char *body, int expected) {
    prepare_file(body);
    assert(node_is_authorized() == expected);
    assert(open_count == 1 && object_closes == 1 && stat_closes == 1);
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
    check("laptop@cluster.example", 1);
    check(" LAPTOP@CLUSTER.EXAMPLE... ", 1);
    check("other@cluster.example", 0);
    check("laptop@other.example", 0);
    check("laptop@cluster.example.evil", 0);
    memset(peer_key, 0xcc, sizeof peer_key);
    check("laptop@cluster.example", 1); /* origin rule follows authenticated key rotation */
    snprintf(list, sizeof list, "%s, laptop@cluster.example", a);
    check(list, 1);
    memset(peer_key, 0xaa, sizeof peer_key);
    snprintf(list, sizeof list, "other@cluster.example,%s", a);
    check(list, 1);
    const char *bad_origins[] = {
        "@cluster.example", "laptop@", "laptop@.", "laptop@@cluster.example",
        "laptop@cluster..example", "laptop@-cluster.example", "laptop@cluster-.example",
        "lap_top@cluster.example", "laptop@cluster.example/evil", "*@cluster.example"
    };
    for (unsigned i = 0; i < sizeof bad_origins / sizeof bad_origins[0]; ++i) {
        snprintf(list, sizeof list, "%s,%s", a, bad_origins[i]);
        check(list, 0); /* malformed origins cannot hide behind a matching key */
    }
    memset(mutated, 'a', 52);
    mutated[52] = 0;
    snprintf(list, sizeof list, "%s%s@cluster.example", mutated, mutated);
    check(list, 0); /* oversized member */
    snprintf(list, sizeof list, "laptop@%s%s.example", mutated, mutated);
    check(list, 0); /* oversized domain label */
    peer_origin = "other@cluster.example";
    check("laptop@cluster.example", 0);
    char label[64], longest[319];
    memset(label, 'a', 63);
    label[63] = 0;
    snprintf(longest, sizeof longest, "%s@%s.%s.%s.%.61s", label, label, label, label, label);
    assert(strlen(longest) == 317);
    peer_origin = longest;
    check(longest, 1); /* maximum canonical origin fits the host buffer */
    peer_origin = "laptop@cluster.example";
    longest[317] = 'a';
    longest[318] = 0;
    check(longest, 0); /* 254-byte domain, despite each label fitting */
    memset(peer_key, 0xaa, sizeof peer_key);
    peer_result = SY_EPERM;
    check(a, 0);
    peer_result = 32;
    check_file("laptop@cluster.example\n", 1);
    assert(poll_count > 0); /* every read goes through SY_EAGAIN and sy_poll */
    check_file("\n \r\n other@example.com\r\n\tlaptop@cluster.example \r\n", 1);
    check_file("laptop@cluster.example", 1);
    check_file("laptop@cluster.example\ninvalid", 0);
    check_file("laptop@cluster.example,other@example.com\n", 0);
    check_file("", 0);
    check_file(" \n\r\n", 0);
    prepare_file("laptop@cluster.example\n");
    ++advertised_size;
    assert(!node_is_authorized()); /* EOF after a match but before advertised size */
    assert(object_closes == 1);
    prepare_file("laptop@cluster.example\n");
    poll_timeout = 1;
    assert(!node_is_authorized() && object_closes == 1);
    prepare_file("laptop@cluster.example\n");
    poll_advance_ns = 6000000000ULL;
    read_chunk = 1;
    assert(!node_is_authorized() && object_closes == 1);
    assert(poll_count == 2); /* total deadline, not a fresh timeout per byte */
    read_chunk = 17;
    prepare_file("laptop@cluster.example\n");
    open_error = 1;
    assert(!node_is_authorized() && object_closes == 0);
    prepare_file("laptop@cluster.example\n");
    stat_error = 1;
    assert(!node_is_authorized() && object_closes == 1 && stat_closes == 0);
    prepare_file("laptop@cluster.example\n");
    read_error = 1;
    assert(!node_is_authorized() && object_closes == 1);
    prepare_file("laptop@cluster.example\n");
    file_kind = "dir";
    assert(!node_is_authorized() && object_closes == 1);
    prepare_file("laptop@cluster.example\n");
    advertised_size = 65537;
    assert(!node_is_authorized() && poll_count == 0 && object_closes == 1);
    prepare_file("laptop@cluster.example\n");
    config = a;
    reported_length = 52;
    assert(!node_is_authorized() && open_count == 0); /* ambiguous sources */
    return 0;
}
