# AWS Vault

[![Downloads](https://img.shields.io/github/downloads/byteness/aws-vault/total)](https://github.com/byteness/aws-vault/releases)
[![Continuous Integration](https://github.com/byteness/aws-vault/workflows/Continuous%20Integration/badge.svg)](https://github.com/byteness/aws-vault/actions)

> [!NOTE]
> This is a maintained fork of https://github.com/99designs/aws-vault which is an abandoned project.
> Contributions are welcome and preferably please open an [issue](https://github.com/ByteNess/aws-vault/issues) first.

AWS Vault is a tool to securely store and access AWS credentials in a development environment.

AWS Vault stores IAM credentials in your operating system's secure keystore and then generates temporary credentials from those to expose to your shell and applications. It's designed to be complementary to the AWS CLI tools, and is aware of your [profiles and configuration in `~/.aws/config`](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-config-files).

Check out the [announcement blog post](https://99designs.com.au/tech-blog/blog/2015/10/26/aws-vault/) for more details.

## Installing

You can install AWS Vault:
- by downloading the [latest release](https://github.com/byteness/aws-vault/releases/latest)
- using [Homebrew](https://formulae.brew.sh/formula/aws-vault): `brew install aws-vault`
- on Windows with [Chocolatey](https://chocolatey.org/packages/aws-vault): `choco install aws-vault` ([repo](https://github.com/gusztavvargadr/aws-vault-chocolatey) by [Gusztáv Varga](https://github.com/gusztavvargadr))
- on [NixOS](https://search.nixos.org/packages?channel=unstable&query=aws-vault): `nix-env -iA nixos.aws-vault`

## Documentation

Config, usage, tips and tricks are available in the [USAGE.md](./USAGE.md) file.

## Vaulting Backends

The supported vaulting backends are:

| Internal name | Backend | How it works | Platforms |
| --- | --- | --- | --- |
| `keychain` | [macOS Keychain](https://support.apple.com/en-au/guide/keychain-access/welcome/mac) | Stores credentials as generic password items in the configured Keychain. Optional biometrics support can use Touch ID to unlock the aws-vault keychain. | macOS |
| `wincred` | [Windows Credential Manager](https://support.microsoft.com/en-au/help/4026814/windows-accessing-credential-manager) | Stores credentials as generic credentials under an aws-vault target-name prefix in Windows Credential Manager. | Windows |
| `winhello` | [Windows Hello](https://support.microsoft.com/en-us/windows/configure-windows-hello-dae28983-8242-bb2a-d3d1-87c9d265a5f0) | Stores encrypted envelopes in Windows Credential Manager. The encryption key is wrapped by Windows Hello / Passport, so reads require PIN/biometrics. | Windows |
| `secret-service` | Secret Service ([GNOME Keyring](https://wiki.gnome.org/Projects/GnomeKeyring), [KWallet](https://apps.kde.org/kwalletmanager5/), ...) | Stores credentials in a Secret Service collection over the desktop session D-Bus. The collection may be unlocked by the desktop keyring service. | Linux |
| `kwallet` | [KWallet](https://apps.kde.org/kwalletmanager5/) | Stores credentials as entries in the configured KWallet folder over the KDE Wallet D-Bus service directly (rather than through the Secret Service API). | Linux |
| `keyctl` | [Linux kernel keyring](https://man7.org/linux/man-pages/man7/keyrings.7.html) | Stores credentials in the Linux kernel key retention service, optionally inside a named keyring for the configured service. | Linux |
| `pass` | [Pass](https://www.passwordstore.org/) | Stores JSON-encoded credential items in a `pass` password store, encrypted by GPG and managed through the `pass` command. | macOS, Linux, FreeBSD |
| `passage` | [Passage](https://github.com/FiloSottile/passage) | Stores JSON-encoded credential items in a Passage store, encrypted with age and managed through the `passage` command. | macOS, Linux, FreeBSD |
| `file` | Encrypted file | Stores one encrypted file per credential under `AWS_VAULT_FILE_DIR` (by default `~/.awsvault/keys/`) using passphrase-based JWE encryption. | All platforms |
| `op-connect` | [1Password Connect](https://developer.1password.com/docs/connect/) | Stores credentials as concealed fields in 1Password items through a 1Password Connect server and token. | Windows, macOS, Linux |
| `op` | [1Password Service Accounts](https://developer.1password.com/docs/service-accounts) | Stores credentials as concealed fields in 1Password items through the 1Password SDK using a service account token. | Windows, macOS, Linux |
| `op-desktop` | [1Password Desktop App](https://developer.1password.com/docs/sdks/desktop-app-integrations/) | Stores credentials as concealed fields in 1Password items through the local 1Password desktop app integration. | Windows, macOS, Linux |

Use the `--backend` flag or `AWS_VAULT_BACKEND` environment variable to specify a backend. Run `aws-vault --help` to see the backends available in your build and environment.

By default, `aws-vault` selects the first available backend for the platform: `wincred` on Windows, `keychain` on macOS, and `secret-service` on Linux when Secret Service is available. On Linux, automatic selection then falls back through `kwallet`, `keyctl`, `pass`, `passage`, and `file`. The 1Password backends are opt-in and are listed after `file`, so choose them explicitly with `--backend` or `AWS_VAULT_BACKEND`.

## Quick start

```shell
# Store AWS credentials for the "jonsmith" profile
$ aws-vault add jonsmith
Enter Access Key Id: ABDCDEFDASDASF
Enter Secret Key: ****************************************
Enter MFA Device ARN (If MFA is not enabled, leave this blank): arn:aws:iam::123456789012:mfa/jonsmith
Added credentials to profile "jonsmith" in vault

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
