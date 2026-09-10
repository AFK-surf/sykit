#include <assert.h>
#include <string.h>
#undef memcpy
#undef memset
#undef memmove
#define memcpy sdk_memcpy
#define memset sdk_memset
#define memmove sdk_memmove
#include <synch.h>
#undef memcpy
#undef memset
#undef memmove
#include "session-deadline.h"
static const char *config;
static sy_u64 wall, mono;
sy_s64 sy_config_get(const char *key, sy_u64 klen, char *out, sy_u64 len) {
    assert(klen == 10 && memcmp(key, "expires_at", 10) == 0);
    if (!config) return SY_ENOENT;
    size_t n = strlen(config);
    memcpy(out, config, n < len ? n : len);
    return (sy_s64)n;
}
sy_u64 sy_now_ms(void) { return wall; }
sy_u64 sy_monotonic_ns(void) { return mono * 1000000; }
int main(void) {
    wall = 1000000; mono = 50;
    const char *bad[] = {NULL, "", "0", "1000", "999", "1001x", "-1", "+1001", " 1001", "4601", "9999999999999999999999"};
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; ++i) {
        config = bad[i]; assert(session_deadline() == 0);
    }
    config = "1001";
    sy_u64 deadline = session_deadline();
    assert(deadline == 1050);
    assert(session_remaining(deadline) == 1000);
    wall = 0; mono = 1049;
    assert(session_remaining(deadline) == 1); /* backwards wall time cannot extend */
    mono = 1050; assert(session_remaining(deadline) == 0);
    mono = 999999; assert(session_remaining(deadline) == 0);
    wall = 1000000; config = "4600";
    assert(session_deadline() != 0); /* exact one-hour maximum */
}
