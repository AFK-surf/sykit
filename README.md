# sykit

Precompiled Synchronicity socket programs. Sources live in `src/`, deployable
BPF ELF objects in `objects/`; both are committed. No compiler is needed to use
them. These run inside Synchronicity's socket runtime, not the Linux kernel.

| Program | Behavior | Access |
| --- | --- | --- |
| `echo` | Echoes binary streams with backpressure; 30-second idle timeout | Any caller able to connect; 16 concurrent streams |
| `whoami` | Prints authenticated origin, device key and peer kind | Any caller able to connect; 8 concurrent streams |
| `ssh-shell` | Interactive `/bin/bash` with PTY; read/write SFTP under `files` | One configured node public key; 4 concurrent connections, one session per connection |

Built against the SDK revision in [UPSTREAM.md](UPSTREAM.md). On the serving
node, inspect objects before activating them to check runtime compatibility and
review capabilities. Existing Synchronicity membership/delegation checks still
apply to every connection.

## Deploy

Run on the serving node (adjust the local space directory):

```sh
(cd objects && sha256sum -c SHA256SUMS)
synch socket inspect objects/echo.o
cp objects/echo.o ~/synchronicity/code/echo.sock
synch socket activate code/echo.sock
```

From a connected node:

```sh
printf 'hello\n' | synch socket connect nas:code/echo.sock
```

Deploy `whoami.o` the same way to inspect the connecting node's authenticated
`peer-key`. Verify that node independently before using its key for SSH access.

## SSH and SFTP

Set `allowed_node_key` to the connecting node's **64-character hexadecimal
Iroh device public key**. This is not an origin name, SSH public key, or
connection metadata. Uppercase and lowercase hex are accepted. Missing,
malformed, or mismatched keys reject the connection before SSH starts.

```sh
synch socket inspect objects/ssh-shell.o
cp objects/ssh-shell.o ~/synchronicity/code/ssh.sock
synch socket activate code/ssh.sock --config allowed_node_key=YOUR_64_HEX_NODE_PUBLIC_KEY
```

From the allowed node:

```sh
ssh -tt -o 'ProxyCommand=synch socket connect %h:code/ssh.sock' nas
sftp -o 'ProxyCommand=synch socket connect %h:code/ssh.sock' nas
```

Keep normal SSH host-key verification enabled. The inner SSH exchange accepts
`none` only after the outer authenticated node passes the gate. The SSH
username does not select an OS user: the shell runs as the Synchronicity daemon
account, with that account's host access. Anyone controlling the allowed node
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
