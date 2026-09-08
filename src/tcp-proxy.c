/* TCP reverse proxy adapted from Synchronicity's splice-proxy example.
 * The shared node-auth gate runs before opening an upstream connection.
 * Upstream host is a manifest capability; only its port is activation config.
 * No caller metadata or payload can select the destination. */
#include <synch.h>
#include "node-auth.h"

#ifndef UPSTREAM_HOST
#define UPSTREAM_HOST "127.0.0.1"
#endif

/* The most one call moves. A bound rather than "whatever both sides allow", so
   a saturated direction cannot keep the loop away from the other one. */
#define CHUNK 32768

/* A host-only rule permits configurable ports on this one literal address. */
SY_MANIFEST("{\"manifest\":1,\"name\":\"tcp-proxy\",\"max_streams\":32,"
            "\"egress\":[\"" UPSTREAM_HOST "\"]}");

static sy_s64 upstream_port(void) {
    char value[6];
    sy_s64 len = sy_config_get(SY_STR("upstream_port"), value, sizeof value);
    if (len <= 0 || len >= (sy_s64)sizeof value) return -1;
    sy_u32 port = 0;
    for (sy_s64 i = 0; i < len; ++i) {
        if (value[i] < '0' || value[i] > '9') return -1;
        port = port * 10 + (sy_u32)(value[i] - '0');
    }
    return port > 0 && port <= 65535 ? (sy_s64)port : -1;
}

SY_ENTRY sy_s64 entry(void) {
  if (!node_is_authorized()) {
    sy_log(SY_STR("tcp-proxy: node authorization denied\n"));
    return 1;
  }
  sy_s64 port = upstream_port();
  if (port < 0) {
    sy_log(SY_STR("tcp-proxy: upstream_port must be between 1 and 65535\n"));
    return 2;
  }
  sy_s64 up = sy_tcp_connect(SY_STR(UPSTREAM_HOST), (sy_u32)port);
  if (up < 0) return 3;
  sy_s64 result = 0;

  /* The whole of this proxy's state. There is no buffer and no remainder; what
     is left to know is which side each direction is waiting on. */
  int caller_done = 0, upstream_done = 0;
  int upward_blocked = 0, downward_blocked = 0;

  while (!(caller_done && upstream_done)) {
    struct sy_pollfd fds[2] = {{SY_SELF, 0, 0}, {up, 0, 0}};
    /* With bytes waiting and no room for them, wait for the room: asking for
       more input would wake immediately on input already delivered. */
    if (!caller_done) {
      if (upward_blocked) fds[1].events |= SY_POLL_OUT;
      else fds[0].events |= SY_POLL_IN;
    }
    if (!upstream_done) {
      if (downward_blocked) fds[0].events |= SY_POLL_OUT;
      else fds[1].events |= SY_POLL_IN;
    }

    /* HUP and ERR are unconditional, so an endpoint no longer part of either
       direction must not stay in the set with events == 0, where a terminal
       event would wake a wait that was about something else. */
    sy_u64 nfds;
    if (fds[0].events == 0) {
      fds[0] = fds[1];
      nfds = 1;
    } else {
      nfds = fds[1].events == 0 ? 1 : 2;
    }

    if (sy_poll(fds, nfds, -1) <= 0) {
      result = 3;
      break;
    }

    if (!caller_done) {
      sy_s64 n = sy_splice(SY_SELF, up, CHUNK);
      if (n == 0) {
        sy_shutdown(up);
        caller_done = 1;
      } else if (n < 0 && n != SY_EAGAIN) {
        result = 3;
        break;
      } else {
        /* Bytes still in the source with a full destination is the one state
           where waiting on the source would spin. It is also the only thing a
           short move leaves behind, which is why the flag is the state. */
        upward_blocked = sy_readable(SY_SELF) > 0 && sy_writable(up) == 0;
      }
    }
    if (!upstream_done) {
      sy_s64 n = sy_splice(up, SY_SELF, CHUNK);
      if (n == 0) {
        sy_shutdown(SY_SELF);
        upstream_done = 1;
      } else if (n < 0 && n != SY_EAGAIN) {
        result = 3;
        break;
      } else {
        downward_blocked = sy_readable(up) > 0 && sy_writable(SY_SELF) == 0;
      }
    }

    sy_u32 revents = 0;
    for (sy_u64 i = 0; i < nfds; i++) revents |= fds[i].revents;
    if (revents & SY_POLL_ERR) {
      result = 3;
      break;
    }
  }

  sy_close(up);
  sy_close(SY_SELF);
  return result;
}
