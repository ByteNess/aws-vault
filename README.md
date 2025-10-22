# AWS Vault

[![Downloads](https://img.shields.io/github/downloads/byteness/aws-vault/total)](https://github.com/byteness/aws-vault/releases)
[![Continuous Integration](https://github.com/byteness/aws-vault/workflows/Continuous%20Integration/badge.svg)](https://github.com/byteness/aws-vault/actions)

> [!NOTE]
> This is a maintained fork of https://github.com/99designs/aws-vault which seems to be an abandoned project.
> Contributions are welcome, but keep in mind this is a side project and maintained on best effort basis!

AWS Vault is a tool to securely store and access AWS credentials in a development environment.

AWS Vault stores IAM credentials in your operating system's secure keystore and then generates temporary credentials from those to expose to your shell and applications. It's designed to be complementary to the AWS CLI tools, and is aware of your [profiles and configuration in `~/.aws/config`](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-config-files).

Check out the [announcement blog post](https://99designs.com.au/tech-blog/blog/2015/10/26/aws-vault/) for more details.

## Installing

You can install AWS Vault:
- by downloading the [latest release](https://github.com/byteness/aws-vault/releases/latest)
- using [Homebrew](https://formulae.brew.sh/formula/aws-vault): `brew install aws-vault`
- on Windows with [Chocolatey](https://chocolatey.org/packages/aws-vault): `choco install aws-vault` ([repo](https://github.com/gusztavvargadr/aws-vault-chocolatey) by [Gusztáv Varga](https://github.com/gusztavvargadr))

## Documentation

Config, usage, tips and tricks are available in the [USAGE.md](./USAGE.md) file.

## Vaulting Backends

The supported vaulting backends are:

* [macOS Keychain](https://support.apple.com/en-au/guide/keychain-access/welcome/mac)
* [Windows Credential Manager](https://support.microsoft.com/en-au/help/4026814/windows-accessing-credential-manager)
* Secret Service ([Gnome Keyring](https://wiki.gnome.org/Projects/GnomeKeyring), [KWallet](https://kde.org/applications/system/org.kde.kwalletmanager5))
* [KWallet](https://kde.org/applications/system/org.kde.kwalletmanager5)
* [Pass](https://www.passwordstore.org/)
* Encrypted file
* [1Password Connect](https://developer.1password.com/docs/connect/)
* [1Password Service Accounts](https://developer.1password.com/docs/service-accounts)

Use the `--backend` flag or `AWS_VAULT_BACKEND` environment variable to specify.

## Quick start

```shell
# Store AWS credentials for the "jonsmith" profile
$ aws-vault add jonsmith
Enter Access Key Id: ABDCDEFDASDASF
Enter Secret Key: %%%

# Execute a command (using temporary credentials)
$ aws-vault exec jonsmith -- aws s3 ls
bucket_1
bucket_2

# open a browser window and login to the AWS Console
$ aws-vault login jonsmith

# List credentials
$ aws-vault list
Profile                  Credentials              Sessions
=======                  ===========              ========
jonsmith                 jonsmith                 -

# Start a subshell with temporary credentials
$ aws-vault exec jonsmith
Starting subshell /bin/zsh, use `exit` to exit the subshell
$ aws s3 ls
bucket_1
bucket_2
```

## How it works

`aws-vault` uses Amazon's STS service to generate [temporary credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html) via the `GetSessionToken` or `AssumeRole` API calls. These expire in a short period of time, so the risk of leaking credentials is reduced.

AWS Vault then exposes the temporary credentials to the sub-process in one of two ways

1. **Environment variables** are written to the sub-process. Notice in the below example how the AWS credentials get written out
   ```shell
   $ aws-vault exec jonsmith -- env | grep AWS
   AWS_VAULT=jonsmith
   AWS_DEFAULT_REGION=us-east-1
   AWS_REGION=us-east-1
   AWS_ACCESS_KEY_ID=%%%
   AWS_SECRET_ACCESS_KEY=%%%
   AWS_SESSION_TOKEN=%%%
   AWS_CREDENTIAL_EXPIRATION=2020-04-16T11:16:27Z
   ```
2. **Local metadata server** is started. This approach has the advantage that anything that uses Amazon's SDKs will automatically refresh credentials as needed, so session times can be as short as possible.
   ```shell
   $ aws-vault exec --server jonsmith -- env | grep AWS
   AWS_VAULT=jonsmith
   AWS_DEFAULT_REGION=us-east-1
   AWS_REGION=us-east-1
   AWS_CONTAINER_CREDENTIALS_FULL_URI=%%%
   AWS_CONTAINER_AUTHORIZATION_TOKEN=%%%
   ```

The default is to use environment variables, but you can opt-in to the local instance metadata server with the `--server` flag on the `exec` command.

## Credential Redaction

AWS Vault can automatically redact AWS credentials from subprocess output to prevent accidental credential leakage. This is similar to the behavior of `op run` from 1Password.

### Configuration

Add an `[aws-vault]` section to your `~/.aws/config` file to enable redaction globally:

```ini
[aws-vault]
redact_secrets = true
```

### Command-line Usage

You can also enable redaction for individual commands using the `--redact` flag:

```shell
$ aws-vault exec --redact myprofile ./my-script.sh
```

The `--redact` flag overrides the configuration file setting.

### How Redaction Works

When redaction is enabled, AWS Vault will:
- Monitor stdout and stderr from subprocesses
- Replace any AWS credentials with `<REDACTED>`
- Match actual credentials being used (access keys, secret keys, session tokens)
- Use exact string matching to prevent false positives
- Handle credentials split across buffer boundaries with a sliding window

This prevents credentials from appearing in logs, terminal history, or process output while maintaining full functionality.

### Advanced Configuration

#### Stderr Window Size

By default, stderr uses a 256-byte sliding window for credential redaction, 
providing near-real-time output while still protecting against credentials 
split at buffer boundaries.

For scripts that output very long credentials (>256 bytes) to stderr, you 
may notice a slight delay in output. You can adjust the window size:

```bash
# Increase stderr window size for more buffering (more secure, slower)
export AWS_VAULT_STDERR_WINDOW_SIZE=512
aws-vault exec --redact myprofile ./my-script.sh

# Decrease for faster stderr output (less secure, faster)
export AWS_VAULT_STDERR_WINDOW_SIZE=128
aws-vault exec --redact myprofile ./my-script.sh
```

**Security Note:** `stdout` always uses the full credential-length window 
regardless of this setting, as it's more likely to contain credential dumps.

#### Child Process Buffering
**Note:** Some programs (like Python) buffer their `stderr` output when not 
connected to a terminal. If you notice delayed `stderr` output even with 
redaction enabled, you may need to configure the child process to disable 
its own buffering. For example:

```bash
# Python: disable buffering
python3 -u script.py

# Ruby: sync stderr
ruby -e '$stderr.sync = true' script.rb
```

### Known Limitations

**Output Ordering:** When redaction is enabled, `stdout` and `stderr` are processed 
by separate goroutines reading from separate pipes. This means that output from 
these streams may appear in a different order than when running the command 
directly in a terminal. This is a fundamental limitation of the pipe-based 
interception approach and does not affect the correctness of redaction.

If your script requires precise `stdout`/`stderr` interleaving, you can redirect 
`stderr` to `stdout` in your script:

```bash
aws-vault exec --redact profile -- bash -c "./script.sh 2>&1"
```
**Note:** This merges the streams, so you won't be able to separately capture `stderr`.

## Roles and MFA

[Best-practice](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#delegate-using-roles) is to [create Roles to delegate permissions](https://docs.aws.amazon.com/cli/latest/userguide/cli-roles.html). For security, you should also require that users provide a one-time key generated from a multi-factor authentication (MFA) device.

First you'll need to create the users and roles in IAM, as well as [setup an MFA device](https://docs.aws.amazon.com/IAM/latest/UserGuide/GenerateMFAConfigAccount.html). You can then [set up IAM roles to enforce MFA](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html#cli-configure-role-mfa).

Here's an example configuration using roles and MFA:

```ini
[default]
region = us-east-1

[profile jonsmith]
mfa_serial = arn:aws:iam::111111111111:mfa/jonsmith

[profile foo-readonly]
source_profile = jonsmith
role_arn = arn:aws:iam::22222222222:role/ReadOnly

[profile foo-admin]
source_profile = jonsmith
role_arn = arn:aws:iam::22222222222:role/Administrator
mfa_serial = arn:aws:iam::111111111111:mfa/jonsmith

[profile bar-role1]
source_profile = jonsmith
role_arn = arn:aws:iam::333333333333:role/Role1
mfa_serial = arn:aws:iam::111111111111:mfa/jonsmith

[profile bar-role2]
source_profile = bar-role1
role_arn = arn:aws:iam::333333333333:role/Role2
mfa_serial = arn:aws:iam::111111111111:mfa/jonsmith
```

Here's what you can expect from aws-vault

| Command                                  | Credentials                 | Cached        | MFA |
|------------------------------------------|-----------------------------|---------------|-----|
| `aws-vault exec jonsmith --no-session`   | Long-term credentials       | No            | No  |
| `aws-vault exec jonsmith`                | session-token               | session-token | Yes |
| `aws-vault exec foo-readonly`            | role                        | No            | No  |
| `aws-vault exec foo-admin`               | session-token + role        | session-token | Yes |
| `aws-vault exec foo-admin --duration=2h` | role                        | role          | Yes |
| `aws-vault exec bar-role2`               | session-token + role + role | session-token | Yes |
| `aws-vault exec bar-role2 --no-session`  | role + role                 | role          | Yes |

## Auto-logout

Since v7.3+ `aws-vault` introduced option to automatically try and do a logout first, before login when executing `aws-vault login <profile>`.

This behavour can be achieved by using `--auto-logout` or `-a` flag! Read more in [USAGE.md](./USAGE.md) file.

## Development

The [macOS release builds](https://github.com/byteness/aws-vault/releases) are code-signed to avoid extra prompts in Keychain. You can verify this with:
```shell
$ codesign --verify --verbose $(which aws-vault)
```

If you are developing or compiling the aws-vault binary yourself, you can [generate a self-signed certificate](https://support.apple.com/en-au/guide/keychain-access/kyca8916/mac) by accessing Keychain Access > Certificate Assistant > Create Certificate -> Certificate Type: Code Signing. You can then sign your binary with:
```shell
$ go build .
$ codesign --sign <Name of certificate created above> ./aws-vault
```

## 🧰 Contributing

Report issues/questions/feature requests on in the [issues](https://github.com/byteness/aws-vault/issues/new) section.

Full contributing [guidelines are covered here](.github/CONTRIBUTING.md).

## Maintainers

* [Marko Bevc](https://github.com/mbevc1)
* Full [contributors list](https://github.com/byteness/aws-vault/graphs/contributors)


## References and Inspiration

 * https://github.com/pda/aws-keychain
 * https://docs.aws.amazon.com/IAM/latest/UserGuide/MFAProtectedAPI.html
 * https://docs.aws.amazon.com/IAM/latest/UserGuide/IAMBestPractices.html#create-iam-users
 * https://github.com/makethunder/awsudo
 * https://github.com/AdRoll/hologram
 * https://github.com/realestate-com-au/credulous
 * https://github.com/dump247/aws-mock-metadata
 * https://boto.readthedocs.org/en/latest/boto_config_tut.html
