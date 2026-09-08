# Upstream

The SDK and initial programs are copied/adapted from Synchronicity commit
`0f9ab0c68055834a54556caea0ba0a9f450972d5`:

- `crates/synch-sock/sdk/synch.h` → `include/synch.h` (unmodified).
- `crates/synch-sock/examples/{echo,whoami,ssh-shell}.c` → `src/`.

`ssh-shell` adds mandatory activation-config node-key authorization before SSH
startup. `whoami` checks host errors and output lengths, propagates write
failures, and omits caller-supplied metadata. Echo retains upstream behavior.

The Docker toolchain follows upstream's clang flags: BPF v3, 16 KiB frames,
and raised normal/cold inline thresholds so local helpers stay in the entry
section. These sources compile directly; future programs with large implicit
memory operations may require the intrinsic lowering in `synch-cc`.

`toolchain/snapshot-ca.pem` contains the public ISRG Root X1 and X2 certificates
from the system CA store, to bootstrap HTTPS access in the minimal Ubuntu image.
APT still checks Ubuntu's signed repository metadata and package hashes.
