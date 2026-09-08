# Script security review

Reviewed on 2026-09-08: the shipped C programs, node-key gate, vendored SDK
helper use, Dockerfile, shell scripts and CI workflow. Host implementations
were consulted to check API contracts. This is a source and regression-test
review, not a proof of absence of vulnerabilities or a comprehensive audit of
Synchronicity, russh, LLVM, Docker or their dependencies.

## Findings addressed

- **SSH parsing:** C-string comparison accepted `sftp` followed by an embedded
  NUL and extra bytes as the exact subsystem name. Comparisons now use the
  full JSON string length and bytes. The node-key gate still applied before
  this request; this was not a node-authentication bypass.
- **SSH resource cleanup:** closing a session before selecting its backend
  retained the connection's only session slot. Receive EOF is now watched
  before a shell or SFTP service starts, releasing the channel and any PTY.
  Exploitation required an authorized node and affected its own connection.
- **Artifact integrity:** a shared mutable image tag could be replaced by
  another build before extraction. Extraction now uses the exact immutable
  image ID returned by this build, with registry pulls disabled.
- **Test helper filesystem handling:** checking existence before copying
  followed dangling symlinks and left a check/write race. Exclusive creation
  now refuses existing paths atomically. This affected a local test helper,
  not the deployed socket runtime.

The CI extraction failure was also fixed: objects live in `/artifacts` so
Docker's injected root files do not enter the artifact comparison.

## Checks

`./scripts/test.sh` covers malformed/mismatched node keys, immutable artifact
selection, stale artifact detection and dangling-symlink refusal.
`./scripts/test-runtime.sh /path/to/synchronicity` executes committed BPF objects
against the actual runtime. It covers transport identity despite spoofed
metadata, binary echo under backpressure, permitted shell/SFTP operations,
embedded-NUL subsystem refusal, rejected exec/environment/forwarding requests,
one active session, abandoned-session recovery, and SFTP read/write/delete
traversal attempts. `./scripts/build.sh --check` performs a fresh amd64 build
and compares the entire artifact directory byte for byte.

## Trust and access

SSH authorization deliberately grants the configured node a shell as the
serving daemon's OS account. SSH usernames do not select or authenticate a
separate OS account. The SFTP scope does not sandbox that shell. Node-key
validation runs before SSH starts; connection metadata never supplies policy.

Runtime admission, authenticated transport, capability enforcement, SFTP path
normalization, process cleanup and resource deadlines remain host obligations.
Echo and whoami are intentionally available to any caller able to reach their
socket. Keep activated script paths, activation configuration, the allowed
node's identity and the build host under operator control. Reproducible builds
and checksums establish consistency, not the trustworthiness of their source.
