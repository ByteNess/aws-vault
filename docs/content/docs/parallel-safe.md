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
- **Keyring lock**: All keyring read/write operations are serialized across processes.

This applies to **all backends** (keychain, file, pass, secret-service, etc.).

## Trade-offs

- Keyring operations are serialized, which adds a small amount of latency per operation. In practice this is negligible because the operations themselves are fast.
- **All concurrent invocations must use `--parallel-safe`**. If some processes enable it and others don't, the unprotected processes ignore the locks entirely. This is undefined behavior and may still cause races. Set `AWS_VAULT_PARALLEL_SAFE=true` in your environment to ensure consistent use.

## The `login` command

The `login` command is intentionally excluded from `--parallel-safe`. Console login sessions are inherently single-use — you cannot meaningfully log in to multiple AWS consoles in parallel — so there is no concurrent-access problem for `--parallel-safe` to solve. The `exec`, `export`, and `rotate` commands all support `--parallel-safe`.

## Limitations

- The keyring lock wait loop cannot be cancelled by the caller because the `keyring.Keyring` interface is not context-aware. If a lock holder hangs (e.g. a stuck `gpg` subprocess in the `pass` backend), waiters will time out after 2 minutes rather than waiting indefinitely.
- SSO rate-limit retries (HTTP 429 on `GetRoleCredentials`) will retry for up to 5 minutes before giving up with an error.
