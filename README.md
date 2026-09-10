# sykit

Precompiled Synchronicity socket programs. Sources live in `src/`, deployable
BPF ELF objects in `objects/`; both are committed. No compiler is needed to use
them. These run inside Synchronicity's socket runtime, not the Linux kernel.

| Program | Behavior | Access |
| --- | --- | --- |
| `echo` | Echoes binary streams with backpressure; 30-second idle timeout | Any caller able to connect; 16 concurrent streams |
| `whoami` | Prints authenticated origin, device key and peer kind, then closes | Any caller able to connect; 8 concurrent streams |
| `tcp-proxy` | Bidirectional TCP forwarding to `127.0.0.1` on a configured port | Same peer allowlist as SSH; 32 concurrent connections |
| `ssh-session` | Expiring interactive shell; no SFTP; existing connections close at the deadline | Pinned agent key; generated private invitation, default 10 minutes |
| `ssh-shell` | Interactive `/bin/bash` with PTY; read/write SFTP under `files` | Configured origins or node public keys; 4 concurrent connections, one session per connection |

Built against the SDK revision in [UPSTREAM.md](UPSTREAM.md). Review the
capabilities shown when activating a socket. Existing Synchronicity
membership/delegation checks still apply to every connection.

## Deploy

Run on the serving node, using an existing space such as `code`:

```sh
synch fetch https://raw.githubusercontent.com/AFK-surf/sykit/main/objects/echo.o code/echo.sock
synch socket activate code/echo.sock
```

From a connected node:

```sh
printf 'hello\n' | synch socket connect nas:code/echo.sock
```

To inspect a connecting node's authenticated `peer-key`, deploy `whoami`:

```sh
synch fetch https://raw.githubusercontent.com/AFK-surf/sykit/main/objects/whoami.o code/whoami.sock
synch socket activate code/whoami.sock
```

Connect with `synch socket connect nas:code/whoami.sock` for identity diagnostics.
Its `peer-key` output is hex; the SSH allowlist below uses z-base-32.

## SSH and SFTP

Set `allowed_peers` to a comma-separated list of authenticated peer origins
and/or node public keys:

- Origins use `host@domain`, as shown by `synch id`. Matching uses the
  authenticated origin, never connection metadata. ASCII case is normalized
  and trailing domain dots are removed; wildcards are not supported.
- Public keys use the **52-character, unpadded z-base-32** node ID printed by
  `synch id` (alphabet `ybndrfg8ejkmcpqxot1uwisza345h769`, not RFC 4648 base32).
  Either case is accepted; hex and `=` padding are rejected.

Spaces, tabs and newlines around entries are allowed. Quote values containing
whitespace. Use at most 16 peers and 1023 bytes of configuration. Empty or
malformed entries invalidate the entire list, even after an entry matches.
Missing configuration or a caller absent from the list rejects the connection
before SSH starts.

```sh
synch fetch https://raw.githubusercontent.com/AFK-surf/sykit/main/objects/ssh-shell.o code/ssh.sock
synch socket activate code/ssh.sock --config 'allowed_peers=laptop@example.com,BASE32_NODE_PUBLIC_KEY'
```

A single origin or key needs no comma. `allowed_node_key` is no longer read;
existing activations must switch to `allowed_peers` when deploying this version.
An origin rule follows whichever node key the membership system authenticates
for that name, including key rotation. A public-key rule pins one device key
regardless of its origin. Verify the peers and the origin's membership authority
before granting shell access.

For a tree-backed allowlist, create a text file with one origin or public key
per line, for example:

```text
laptop@example.com
workstation@example.com
BASE32_NODE_PUBLIC_KEY
```

Publish it into the serving node's tree and configure its path:

```sh
synch put ssh-allowlist.txt code/ssh-allowlist.txt
synch socket activate code/ssh.sock --config allowlist=code/ssh-allowlist.txt
```

Configure exactly one of `allowed_peers` or `allowlist`. With `allowlist`, the
server reads the selected tree file for every new connection; changing its
contents requires no socket rebuild. Each connection reads one object snapshot.
Existing SSH sessions are not revoked by later changes. Protect writes to this
path: anyone who can change this file can grant shell access as the daemon's
OS account. Consider this when selecting a path writable through SFTP.

Files may contain up to 64 KiB and 1,024 nonblank peer entries, with at most
1,023 bytes per line before the LF. CRLF, blank lines, surrounding whitespace
and a final line without a newline are supported. Comments and comma-separated
entries are not supported in files. The entire file must be valid; missing,
unreadable, oversized, malformed or incompletely read files deny access.
Reading has a 10-second total deadline. Both source settings together also
deny access; a failed file read never falls back to inline peers.

From an allowed node:

```sh
ssh -tt -o 'ProxyCommand=synch socket connect %h:code/ssh.sock' nas
sftp -o 'ProxyCommand=synch socket connect %h:code/ssh.sock' nas
```

Keep normal SSH host-key verification enabled. The inner SSH exchange accepts
`none` only after the outer authenticated node passes the gate. The SSH
username does not select an OS user: the shell runs as the Synchronicity daemon
account, with that account's host access. Anyone controlling an allowed node
and able to use its Synchronicity identity can obtain that access.

SFTP can recursively read, create, replace and delete within the declared
`files` tree scope; writes commit on close, bounded to 16 MiB per commit. This
scope limits SFTP, **not the shell's filesystem access**. The serving node must
have `/bin/bash` and the intended `files` space. SSH exec commands, environment
requests and forwarding are rejected; use an interactive PTY for the shell.
SSH connections use the runtime's configured deadlines and resource limits.

To change the executable or SFTP scope, edit the source defaults and rebuild;
review the resulting manifest. Do not grant untrusted callers write access to
an activated socket path: replacing its bytes deploys a new program immediately.
Activation configuration stays on the serving node; it is not embedded in the
published object.

## Temporary agent support sessions

An agent can generate a script for a consenting user, then open an interactive
shell on that user's machine until a fixed expiry. This is a **temporary session**,
not an exactly-once command executor. SSH `exec` is still rejected; use the PTY
shell to run several commands. Existing `ssh-shell` activations are unchanged.

On an enrolled agent node with Synchronicity running and Python 3 available:

```sh
python3 tools/make-session.py --seconds 600 --output /private/path/support.py
```

The generator checks the agent's identity, creates a new isolated device key,
trusts only the issuing agent, and gives that key a delegation for a **new empty
space** until the invitation expiry. It does not grant access to the agent's
existing file spaces or add a permanent network member. No control-plane API key,
join key or agent private key is included. `--data-dir` selects an existing agent
node; `--synch` selects its binary. The output is created exclusively, mode 0600.

**Send the generated script privately to the intended user. It embeds a temporary
device secret.** Anyone holding a copy can impersonate that temporary node until
the delegation expires. It is an expiring invitation, not a replay-proof ticket:
do not reuse it or post it to a public thread. Generate a fresh one for each user.
The lifetime is 30–3600 seconds **from generation**, including download/setup time;
the default is 600. Delayed delivery does not extend the grant.

The user runs:

```sh
python3 support.py
```

After explicit `yes` consent, it downloads the official runtime matching the
agent's version, verifies an embedded SHA-256 checksum, restores only the temporary
identity into a private temporary directory, and starts a foreground-owned daemon.
It publishes/activates `ssh-session.o` as `temporary-shell`, allowing only the
agent's public key, and prints `READY`. No sudo, permanent binary installation,
shell-profile change, SSH configuration change or startup service is needed.
Requires Python 3, curl, `/bin/bash`, macOS or glibc Linux; v0.1.10 Linux archives
require glibc 2.39. The generator uses release checksums directly, not the
rate-limited unauthenticated `releases/latest` API.

The generator prints the exact agent-side SSH command and an early network
revocation command. Keep SSH host-key verification enabled. The user can press
Ctrl-C or close the terminal to stop access. The supervisor stops the temporary
daemon and removes its data/binary on normal expiry, SIGINT, SIGHUP and SIGTERM.
Delete the invitation file after use; the script does not delete itself.

`ssh-session` independently requires an `expires_at` Unix-second activation
setting, rejects expired/malformed/missing or >1-hour deadlines, and closes
**existing** sessions at the deadline as well as refusing new ones. Its admitted
session timer is monotonic, so moving the wall clock backwards does not extend
it. This is not just a white-list edit or a timer around the SSH client. The
outer supervisor also bounds its setup and lifetime using wall and monotonic time.
The variant declares a process capability only: no SFTP, tree writes or egress.

### Security and cleanup boundaries

The shell runs as the user's account, **not in a sandbox**. It can modify files,
read that account's secrets and start detached processes. Expiry closes the
connection and the runtime terminates/reaps its direct shell with best-effort
process-group cleanup; it cannot undo changes or guarantee cleanup of detached
descendants. Do not use it to execute untrusted agent code.

The grant expires in signed delegation state without a cleanup service on the
agent. `synch delegate rm <temporary-key>` revokes early network access; user-side
Ctrl-C is the explicit local shutdown. Removing/expiring delegation does not
serve as the session timer: the program and supervisor enforce that separately.
SIGKILL, machine crashes and power loss can prevent supervisor cleanup. The
program's own deadline still prevents a surviving daemon from providing a new
unexpired shell after the invitation deadline; leftover local temporary files
may require manual removal. Local clock integrity is part of admission trust.

## TCP reverse proxy

`tcp-proxy` forwards an authenticated Synchronicity stream to a TCP service on
the serving node. It uses the same `allowed_peers` or tree-backed `allowlist`
settings described above, and checks authorization before connecting upstream.

```sh
synch fetch https://raw.githubusercontent.com/AFK-surf/sykit/main/objects/tcp-proxy.o code/tcp-proxy.sock
synch socket activate code/tcp-proxy.sock --config 'allowed_peers=laptop@example.com' --config upstream_port=8080
```

Or use a tree allowlist:

```sh
synch socket activate code/tcp-proxy.sock --config allowlist=code/tcp-allowlist.txt --config upstream_port=8080
```

From an allowed node, expose the service to local applications:

```sh
synch socket connect nas:code/tcp-proxy.sock --listen 127.0.0.1:18080
```

For an HTTP service, open `http://127.0.0.1:18080`. The proxy carries arbitrary
TCP bytes; it does not terminate TLS, interpret HTTP, or send a PROXY-protocol
header. Applications using the local listener share the forwarding node's
identity. The two stream directions drain independently, so a half-close does
not truncate a pending reply.

`upstream_port` is required and must be decimal 1–65535. The committed object
pins its upstream host to `127.0.0.1`; its manifest declares that host with all
ports permitted, while activation config selects one port. Caller metadata and
payload cannot override either. To use a different host, change `UPSTREAM_HOST`
in `src/tcp-proxy.c`, rebuild, and review its changed egress declaration.
Allowlisted nodes receive full protocol access to the selected service, so
protect the activation config, socket path and any allowlist file.

The runtime's idle and resource limits apply. Program exit codes are 0 for
clean completion, 1 for denied authorization, 2 for invalid/missing port config,
and 3 for connection or forwarding failure.

## Rebuild and verify

```sh
./scripts/test.sh
./scripts/build.sh
./scripts/build.sh --check
```

Requires Docker, or `CONTAINER_ENGINE=podman`. The Dockerfile pins the Ubuntu
image digest, compiler host to `linux/amd64`, and signed Ubuntu package snapshot
to `20260901T000000Z`. ARM hosts need amd64 emulation; Docker Desktop includes
it. Outputs target little-endian BPF v3 and work on supported Synchronicity
hosts regardless of their CPU architecture. Compilation uses clang 18, fixed
paths and locale, no debug data, and 16 KiB stack frames. Builds compile only
checked-in inputs and extract `/artifacts` from the exact image produced by
that build. The test script requires a C compiler and Python 3.

`--check` rebuilds into a temporary directory and compares every byte and the
complete output file set with `objects/`. Commit changed `.c`, headers, `.o`
and `SHA256SUMS` together. Checksums detect changes; obtain this repository from
a trusted source. CI checks authentication and artifact reproducibility.

For runtime integration tests against a local Synchronicity checkout, see
`tests/runtime.rs` and `scripts/test-runtime.sh`.

See [SECURITY.md](SECURITY.md) for the security review, regression coverage and
trust assumptions.
