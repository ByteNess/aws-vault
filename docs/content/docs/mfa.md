---
title: MFA
weight: 7
---

To enable MFA for a profile, specify the `mfa_serial` in `~/.aws/config`. You can retrieve the MFA's serial (ARN) in the
web console, under IAM > Users > `<User>` > Security Configuration. If you have an account with an MFA associated, but
you don't provide the ARN, you are unable to call IAM services, even if you have the correct permissions to do so.

AWS Vault will attempt to re-use a `GetSessionToken` between profiles that share a common `mfa_serial`. In the following
example, aws-vault will cache and re-use sessions between role1 and role2. This means you don't have to continually
enter MFA codes if the MFA method is the same.

```ini
[profile tom]
mfa_serial = arn:aws:iam::111111111111:mfa/tom

[profile role1]
source_profile = tom
role_arn = arn:aws:iam::22222222222:role/role1
mfa_serial = arn:aws:iam::111111111111:mfa/tom

[profile role2]
source_profile = tom
role_arn = arn:aws:iam::33333333333:role/role2
mfa_serial = arn:aws:iam::111111111111:mfa/tom
```

Be sure to specify the `mfa_serial` for the source profile (in the above example `tom`) so that aws-vault can match the
common `mfa_serial`.

You can also set the `mfa_serial` with the environment variable `AWS_MFA_SERIAL`.

## Gotchas with MFA config

aws-vault v4 would inherit the `mfa_serial` from the `source_profile`. While this was intuitive for some, it made
certain configurations difficult to express and is different behaviour to the aws-cli.

aws-vault v5 corrected this problem. The `mfa_serial` must be specified for _each_ profile, the same way the aws-cli
interprets the configuration. If you wish to avoid specifying the `mfa_serial` for each profile, consider using the
`mfa_serial` in the `[default]` section, the `AWS_MFA_SERIAL` environment variable, or
[`include_profile`](/docs/config#include_profile). For example:

```ini
[profile jon]
mfa_serial = arn:aws:iam::111111111111:mfa/jon
source_profile=jon

[profile role1]
role_arn = arn:aws:iam::22222222222:role/role1
include_profile = jon

[profile role2]
role_arn = arn:aws:iam::33333333333:role/role2
include_profile = jon
```
