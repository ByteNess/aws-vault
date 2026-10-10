---
title: Parallel-safe mode
linkTitle: Parallel-safe mode
weight: 9
---

When running many `aws-vault` processes in parallel (e.g. Terraform with hundreds of `credential_process` invocations), concurrent access to the secret store and SSO browser flows can cause errors:

- **Browser storms**: Multiple processes each open a browser tab for the same SSO login, overwhelming AWS and triggering HTTP 500 errors.
- **Secret store races**: Concurrent writes to the same keyring entry cause "item already exists" errors or partial reads.

The `--parallel-safe` flag (or `AWS_VAULT_PARALLEL_SAFE=true`) enables cross-process locking to prevent these issues:

- **SSO token lock**: Only one process per SSO Start URL opens a browser tab; others wait for the cached token.
- **Session cache lock**: Only one process writes back to a given session cache entry at a time.
- **Keyring lock**: All keyring read/write operations are serialized across processes. A separate session keyring (`--session-backend` or the session overrides) gets its own lock, so the two stores do not wait on each other.

This applies to **all backends** (keychain, file, pass, secret-service, etc.).

The lock files live in a per-user directory, `aws-vault/locks` under the user cache directory: `~/Library/Caches` on macOS, `$XDG_CACHE_HOME` or `~/.cache` on Linux, and `%LocalAppData%` on Windows. Locks therefore never cross user accounts on a shared host, and other local users cannot create or hold them.

## Trade-offs

- Keyring operations are serialized, which adds a small amount of latency per operation. In practice this is negligible because the operations themselves are fast.
- **All concurrent invocations must use `--parallel-safe`**. If some processes enable it and others don't, the unprotected processes ignore the locks entirely. This is undefined behavior and may still cause races. Set `AWS_VAULT_PARALLEL_SAFE=true` in your environment to ensure consistent use.

## Commands

`exec`, `export`, `login` and `rotate` all honour `--parallel-safe`. A console session from `login` is single-use, but getting one still reads and writes the same session cache and SSO token as `exec` and `export`, and can start the same SSO sign-in, so it takes the same locks.

## Limitations

- The keyring lock wait loop cannot be cancelled by the caller because the `keyring.Keyring` interface is not context-aware. If a lock holder hangs (e.g. a stuck `gpg` subprocess in the `pass` backend), waiters will time out after 2 minutes rather than waiting indefinitely.
- SSO rate-limit retries (HTTP 429 on `GetRoleCredentials`) will retry for up to 5 minutes before giving up with an error.
- A process waiting for the SSO token lock waits up to 11 minutes, so that it outlasts a holder that is still in a browser sign-in (which gives up after 10 minutes). A process waiting for a session cache lock waits up to 16 minutes, since its holder may be in that sign-in and then in the 429 retries above. A holder that exits or is killed releases its lock immediately, so these long waits only apply while the holder is still working.
