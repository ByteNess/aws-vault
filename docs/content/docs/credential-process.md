---
title: Using credential_process
linkTitle: credential_process
weight: 10
---

The
[AWS CLI config](https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes)
supports sourcing credentials directly from an external process, using `credential_process`.

## Invoking `aws-vault` via `credential_process`

```ini
[profile home]
credential_process = aws-vault export --format=json home
```

If `mfa_serial` is set, please define the prompt driver (for example `osascript` for macOS), else the prompt will not
show up.

```ini
[profile work]
mfa_serial = arn:aws:iam::123456789012:mfa/jonsmith
credential_process = aws-vault --prompt=osascript export --format=json work
```

Note that `credential_process` is designed for retrieving master credentials, while aws-vault outputs STS credentials by
default. If a role is present, the AWS CLI/SDK uses the master credentials from the `credential_process` to generate STS
credentials itself. So depending on your use-case, it might make sense for aws-vault to output master credentials by
using a profile without a role and the `--no-session` argument. For example:

```ini
[profile jon]
credential_process = aws-vault export --no-session --format=json jon

[profile work]
mfa_serial = arn:aws:iam::123456789012:mfa/jonsmith
role_arn = arn:aws:iam::33333333333:role/role2
source_profile = jon
```

If you're using `credential_process` in your config to invoke `aws-vault exec` you should not use `aws-vault exec` on
the command line to execute commands directly - the AWS SDK executes `aws-vault` for you.

## Invoking `credential_process` via `aws-vault`

When executing a profile via `aws-vault exec` that has `credential_process` set, `aws-vault` will execute the specified
command to obtain a credential. This will allow `aws-vault` to cache credentials obtained via `credential_process`.
