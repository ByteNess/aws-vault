---
title: Config
weight: 3
---

## AWS config file

aws-vault uses your `~/.aws/config` to load AWS config. This should work identically to the config specified by the
[aws-cli docs](https://docs.aws.amazon.com/cli/latest/topic/config-vars.html).

### `include_profile`

(Note: aws-vault v5 calls this `parent_profile`)

AWS Vault also recognises an extra config variable, `include_profile`, which is not recognised by the aws-cli. This
variable allows a profile to load configuration horizontally from another profile.

This is a flexible mechanism for more complex configurations.

For example you can use it in "mixin" style where you import a common fragment. In this example, the `root`, `order-dev`
and `order-staging-admin` profiles include the `region`, `mfa_serial` and `source_profile` configuration from `common`.

```ini
; The "common" profile here operates as a "config fragment" rather than a profile
[profile common]
region=eu-west-1
mfa_serial=arn:aws:iam::123456789:mfa/johnsmith
source_profile = root

[profile root]
include_profile = common

[profile order-dev]
include_profile = common
role_arn=arn:aws:iam::123456789:role/developers

[profile order-staging-admin]
include_profile = common
role_arn=arn:aws:iam::123456789:role/administrators
```

Or you could use it in "parent" style where you conflate the fragment with the profile. In this example the `order-dev`
and `order-staging-admin` profiles include the `region`, `mfa_serial` and `source_profile` configuration from `root`,
while also using the credentials stored against the `root` profile as the source credentials `source_profile = root`

```ini
; The "root" profile here operates as a profile, a config fragment as well as a source_profile
[profile root]
region=eu-west-1
mfa_serial=arn:aws:iam::123456789:mfa/johnsmith
source_profile = root

[profile order-dev]
include_profile = root
role_arn=arn:aws:iam::123456789:role/developers

[profile order-staging-admin]
include_profile = root
role_arn=arn:aws:iam::123456789:role/administrators
```

### `session_tags` and `transitive_session_tags`

It is possible to set [session tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html) when
`AssumeRole` is used. Two custom config variables could be defined for that: `session_tags` and
`transitive_session_tags`. The former defines a comma separated key=value list of tags and the latter is a comma
separated list of tags that should be persisted during role chaining:

```ini
[profile root]
region=eu-west-1

[profile order-dev]
source_profile = root
role_arn=arn:aws:iam::123456789:role/developers
session_tags = key1=value1,key2=value2,key3=value3
transitive_session_tags = key1,key2
```

### `source_identity`

It is possible to set
[source identity](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html)
when `AssumeRole` is used. Custom config variable `source_identity` allows you to set the value.

```ini
[profile root]
region=eu-west-1

[profile order-dev]
source_profile = root
role_arn=arn:aws:iam::123456789:role/developers
source_identity=your_user_name
```

### `mfa_process`

If you have a method to generate an MFA token, you can use it with `aws-vault` by specifying the `mfa_process` option in
a profile of your `~/.aws/config` file. The value of `mfa_process` should be a command that will output the MFA token to
stdout.

For example, to use `pass` to retrieve an MFA token from a password store entry, you could use the following:

```ini
[profile foo]
mfa_serial=arn:aws:iam::123456789:mfa/johnsmith
mfa_process=pass otp my_aws_mfa
```

Or another example using 1Password

```ini
[profile foo]
mfa_serial=arn:aws:iam::123456789:mfa/johnsmith
mfa_process=op item get my_aws_mfa --otp
```

WARNING: Use of this option runs against security best practices. It is recommended that you use a dedicated MFA device.

## Environment variables

To configure the default flag values of `aws-vault` and its subcommands:

| Variable | Description | Flag |
| --- | --- | --- |
| `AWS_VAULT_BACKEND` | Secret backend to use | `--backend` |
| `AWS_VAULT_BIOMETRICS` | Use biometric authentication using TouchID, if supported | `--biometrics` |
| `AWS_VAULT_KEYCHAIN_NAME` | Name of macOS keychain to use | `--keychain` |
| `AWS_VAULT_AUTO_LOGOUT` | Enable auto-logout when doing `login` | `--auto-logout` |
| `AWS_VAULT_PROMPT` | Prompt driver to use | `--prompt` |
| `AWS_VAULT_PASS_PASSWORD_STORE_DIR` | Pass password store directory | `--pass-dir` |
| `AWS_VAULT_PASS_CMD` | Name of the pass executable | `--pass-cmd` |
| `AWS_VAULT_PASS_PREFIX` | Prefix to prepend to the item path stored in pass | `--pass-prefix` |
| `AWS_VAULT_FILE_DIR` | Directory for the "file" password store | `--file-dir` |
| `AWS_VAULT_FILE_PASSPHRASE` | Password for the "file" password store | — |
| `AWS_VAULT_OP_TIMEOUT` | Timeout for 1Password Service Account operations | `--op-timeout` |
| `AWS_VAULT_OP_VAULT_ID` | UUID of the 1Password vault | `--op-vault-id` |
| `AWS_VAULT_OP_ITEM_TITLE_PREFIX` | Prefix to prepend to 1Password item titles | `--op-item-title-prefix` |
| `AWS_VAULT_OP_ITEM_TAG` | Tag to apply to 1Password items | `--op-item-tag` |
| `AWS_VAULT_OP_CONNECT_HOST` | 1Password Connect server HTTP(S) URI | `--op-connect-host` |
| `AWS_VAULT_OP_CONNECT_TOKEN` | 1Password Connect server access token | — |
| `AWS_VAULT_OP_SERVICE_ACCOUNT_TOKEN` | 1Password service account token | — |
| `AWS_VAULT_OP_DESKTOP_ACCOUNT_ID` | 1Password Desktop App account name or account UUID | `--op-desktop-account-id` |
| `AWS_VAULT_PROTON_PASS_SHARE_ID` | Share ID of the Proton Pass vault to use | `--proton-pass-share-id` |
| `AWS_VAULT_PROTON_PASS_ITEM_TITLE_PREFIX` | Prefix to prepend to Proton Pass item titles | `--proton-pass-item-title-prefix` |
| `AWS_VAULT_PROTON_PASS_API_BASE` | Proton API base URL | `--proton-pass-api-base` |
| `AWS_VAULT_PROTON_PASS_TIMEOUT` | Timeout for Proton Pass API operations | `--proton-pass-timeout` |
| `AWS_VAULT_PROFILE_ENV` | Set `AWS_PROFILE` instead of injecting `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` to allow profile-based SDK auth | `profile-env` (for `exec`) |
| `AWS_CONFIG_FILE` | The location of the AWS config file | — |
| `AWS_VAULT_STDOUT` | Print login URL to stdout instead of opening in default browser | `--stdout` |

To override the AWS config file (used in the `exec`, `login` and `rotate` subcommands):

| Variable | Description |
| --- | --- |
| `AWS_REGION` | The AWS region |
| `AWS_DEFAULT_REGION` | The AWS region, applied only if `AWS_REGION` isn't set |
| `AWS_STS_REGIONAL_ENDPOINTS` | STS endpoint resolution logic, must be "regional" or "legacy" |
| `AWS_ENDPOINT_URL` | The AWS endpoint URL to use |
| `AWS_MFA_SERIAL` | The identification number of the MFA device to use |
| `AWS_ROLE_ARN` | Specifies the ARN of an IAM role in the active profile |
| `AWS_ROLE_SESSION_NAME` | Specifies the name to attach to the role session in the active profile |

To override session durations (used in `exec` and `login`):

| Variable | Description | Default |
| --- | --- | --- |
| `AWS_SESSION_TOKEN_TTL` | Expiration time for the `GetSessionToken` credentials | `1h` |
| `AWS_CHAINED_SESSION_TOKEN_TTL` | Expiration time for the `GetSessionToken` credentials when chaining profiles | `8h` |
| `AWS_ASSUME_ROLE_TTL` | Expiration time for the `AssumeRole` credentials | `1h` |
| `AWS_FEDERATION_TOKEN_TTL` | Expiration time for the `GetFederationToken` credentials | `1h` |
| `AWS_MIN_TTL` | The minimum expiration time allowed for a credential | `5m` |

Note that the session durations above expect a unit after the number (e.g. 12h or 43200s).

To override or set session tagging (used in `exec`):

| Variable | Description |
| --- | --- |
| `AWS_SESSION_TAGS` | Comma separated key-value list of tags passed with the `AssumeRole` call, overrides `session_tags` profile config variable |
| `AWS_TRANSITIVE_TAGS` | Comma separated list of transitive tags passed with the `AssumeRole` call, overrides `transitive_session_tags` profile config variable |

To override or set the source identity (used in `exec` and `login`):

| Variable | Description |
| --- | --- |
| `AWS_SOURCE_IDENTITY` | Specifies the source identity for assumed role sessions |
