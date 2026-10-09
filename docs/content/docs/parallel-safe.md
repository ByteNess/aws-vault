---
title: Parallel-safe mode
linkTitle: Parallel-safe mode
weight: 9
---

When running many `aws-vault` processes in parallel (e.g. Terraform with hundreds of `credential_process` invocations), concurrent access to the secret store and SSO browser flows can cause errors:

- **Browser storms**: Multiple processes each open a browser tab for the same SSO login, overwhelming AWS and triggering HTTP 500 errors.
- **Secret store races**: Concurrent writes to the same keyring entry cause "item already exists" errors or partial reads.

The `--parallel-safe` flag (or `AWS_VAULT_PARALLEL_SAFE=true`) enables cross-process locking to prevent these issues:

- **SSO token lock**: Only one process per SSO Start URL refreshes the OIDC token or opens a browser tab to sign in; others wait for the cached token.
- **Session cache lock**: Only one process writes back to a given session cache entry at a time.
- **Keyring lock**: All keyring read/write operations are serialized across processes, for both the primary keyring and a separate session keyring (`--session-backend`).

This applies to **all backends** (keychain, file, pass, secret-service, etc.).

It applies to every command that reads or writes credentials: `exec`, `export`, `login`, and `rotate`.

Lock files live in a per-user directory: `$XDG_RUNTIME_DIR/aws-vault` (on Linux, `/run/user/$UID/aws-vault` when `XDG_RUNTIME_DIR` is unset), or the per-user temporary directory on macOS and Windows. On Linux and other Unix systems without a runtime directory, aws-vault uses `/tmp/aws-vault-$UID` and refuses to use it unless it is a directory owned by the current user with `0700` permissions.

## Trade-offs

- Keyring operations are serialized, which adds a small amount of latency per operation. In practice this is negligible because the operations themselves are fast.
- **All concurrent invocations must use `--parallel-safe`**. If some processes enable it and others don't, the unprotected processes ignore the locks entirely. This is undefined behavior and may still cause races. Set `AWS_VAULT_PARALLEL_SAFE=true` in your environment to ensure consistent use.

## Limitations

- Waiting processes have no time limit: they wait as long as the lock holder is working, which can include a browser sign-in or an MFA or keychain prompt, and print a "Waiting for … lock" message while they do. A lock is released as soon as its holder exits, so a crashed process cannot leave it held. If a lock holder hangs (e.g. a stuck `gpg` subprocess in the `pass` backend), stop it or press Ctrl-C in the waiting process.
- SSO rate-limit retries (HTTP 429 on `GetRoleCredentials`) will retry for up to 5 minutes before giving up with an error.
