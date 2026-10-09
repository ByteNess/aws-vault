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

The keyring lock applies to every command that uses the keyring. `exec`, `export`, `login`, and `rotate` also take the SSO token and session cache locks.

Lock files live in `aws-vault` under the runtime directory: `$XDG_RUNTIME_DIR` if it is set, otherwise `/run/user/$UID` on Linux and the per-user temporary directory on macOS and Windows. The runtime directory must belong to the current user and be writable only by them. If it is missing or isn't private, aws-vault uses `/tmp/aws-vault-$UID` instead, and refuses to use that unless it is a directory owned by the current user with `0700` permissions.

## Trade-offs

- Keyring operations are serialized, which adds a small amount of latency per operation. In practice this is negligible because the operations themselves are fast.
- **All concurrent invocations must use `--parallel-safe`**. If some processes enable it and others don't, the unprotected processes ignore the locks entirely. This is undefined behavior and may still cause races. Set `AWS_VAULT_PARALLEL_SAFE=true` in your environment to ensure consistent use.

## Stress testing

`contrib/scripts/aws-vault-parallel-safe-stress.sh` checks `--parallel-safe` against your own IAM Identity Center portals. Given start URLs and their regions, it finds every account and role you can reach through them, then runs `aws-vault export` for all of them in parallel against a temporary credential store. It fails if any export fails or if more than one SSO sign-in starts per start URL:

```shell
contrib/scripts/aws-vault-parallel-safe-stress.sh --parallel 50 \
  https://d-1234567890.awsapps.com/start=us-east-1
```

Finding the profiles needs the AWS CLI v2 and jq; it is done by `aws-vault-collect-sso-profiles.sh`, which signs in with `aws sso login` where `~/.aws/sso/cache` has no valid token, using the device code flow when `AWS_VAULT_DEVICE_CODE` is true. To test a fixed set of profiles instead, pass `--config FILE`, which needs only aws-vault. `--role NAME` limits the run to one role, `same` mode runs many `exec` processes for one profile to race the session cache, and `--no-parallel-safe` runs the same workload without locking for comparison.

The run signs in to each start URL once through your browser. Pass `--store-dir DIR` to keep the temporary store, so a second run reuses its OIDC tokens and sessions.

## Limitations

- Waiting processes have no time limit: they wait as long as the lock holder is working, which can include a browser sign-in or an MFA or keychain prompt, and print a "Waiting for … lock" message while they do. A lock is released as soon as its holder exits, so a crashed process cannot leave it held. If a lock holder hangs (e.g. a stuck `gpg` subprocess in the `pass` backend), stop it or press Ctrl-C in the waiting process.
- SSO rate-limit retries (HTTP 429 on `GetRoleCredentials`) will retry for up to 5 minutes before giving up with an error.
