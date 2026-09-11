#ifndef SYKIT_SESSION_DEADLINE_H
#define SYKIT_SESSION_DEADLINE_H
/* expires_at is an absolute Unix second. Invitations last at most one hour;
 * the creator normally issues ten minutes. Wall time admits, monotonic time
 * prevents a backwards clock adjustment extending an established session. */
static sy_u64 session_deadline(void) {
    char value[12];
    sy_s64 n = sy_config_get(SY_STR("expires_at"), value, sizeof value);
    if (n <= 0 || n > 11) return 0;
    sy_u64 seconds = 0;
    for (sy_s64 i = 0; i < n; ++i) {
        if (value[i] < '0' || value[i] > '9') return 0;
        seconds = seconds * 10 + (sy_u64)(value[i] - '0');
    }
    sy_u64 now = sy_now_ms(), expires = seconds * 1000;
    if (expires <= now || expires - now > 3600000) return 0;
    return sy_monotonic_ns() / 1000000 + expires - now;
}
static sy_s64 session_remaining(sy_u64 deadline) {
    sy_u64 now = sy_monotonic_ns() / 1000000;
    return now < deadline ? (sy_s64)(deadline - now) : 0;
}
#endif
