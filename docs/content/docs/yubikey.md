---
title: Using a Yubikey
linkTitle: Yubikey
weight: 11
---

Yubikeys can be used with AWS Vault via Yubikey's OATH-TOTP support. TOTP is necessary because FIDO-U2F is unsupported
on the AWS CLI and SDKs; even though it's supported on the AWS Console.

## Prerequisites

 1. [A Yubikey that supports OATH-TOTP](https://support.yubico.com/support/solutions/articles/15000006419-using-your-yubikey-with-authenticator-codes)
 1. `ykman`, the [YubiKey Manager CLI](https://github.com/Yubico/yubikey-manager) tool.

You can verify these prerequisites by running `ykman info` and checking `OATH` is enabled.

## Setup

 1. Log into the AWS Management Console with your IAM user credentials, and navigate to IAM, Users and pick your user.
 1. Select the tab _Security Credentials_.
 1. Under _Multi-factor authentication (MFA)_, click `Assign MFA device` and add a _Authenticator app_ MFA device.
 1. Instead of showing the QR code, click on `Show secret key` and copy the key.
 1. On a command line, run:

    ```shell
    ykman oath accounts add -t arn:aws:iam::${ACCOUNT_ID}:mfa/${MFA_DEVICE_NAME}
    ```

    replacing `${ACCOUNT_ID}` with your AWS account ID and `${MFA_DEVICE_NAME}` with the name you gave to the MFA
    device. It will prompt you for a base32 text and you can input the key from step 3. Notice the above command uses
    `-t` which requires you to touch your YubiKey to generate authentication codes.
 1. Now you have to enter two consecutive MFA codes into the AWS website to assign your key to your AWS login. Just run
    `ykman oath accounts code arn:aws:iam::${ACCOUNT_ID}:mfa/${MFA_DEVICE_NAME}` to get an authentication code. The
    codes are re-generated every 30 seconds, so you have to run this command twice with about 30 seconds in between to
    get two distinct codes. Enter the two codes in the AWS form and click `Assign MFA`.

A script can be found at
[contrib/scripts/aws-iam-create-yubikey-mfa.sh](https://github.com/ByteNess/aws-vault/blob/main/contrib/scripts/aws-iam-create-yubikey-mfa.sh)
to automate the process. Note that this script requires your `$MFA_DEVICE_NAME` to be your IAM username as the `aws iam
enable-mfa-device` command in the CLI does not yet offer specifying the name. When only one MFA device was allowed per
IAM user, the `$MFA_DEVICE_NAME` would always be your IAM username.

In case of TOTP being out of sync (AWS API doesn't accept MFA codes), a yubikey resync script can be found at
[contrib/scripts/aws-iam-resync-yubikey-mfa.sh](https://github.com/ByteNess/aws-vault/blob/main/contrib/scripts/aws-iam-resync-yubikey-mfa.sh)
to resync the yubikey with AWS. As above, this script requires your `$MFA_DEVICE_NAME` to be your IAM username.

Note that each `[profile <name>]` in your `~/.aws/config` only supports one `mfa_serial` entry. If you wish to use
multiple Yubikeys, or mix and match MFA devices, you'll need to add a profile for each method.

## Usage

Using the `ykman` prompt driver, aws-vault will execute `ykman` to generate tokens for any profile in your `.aws/config`
using an `mfa_device`.

```shell
aws-vault exec --prompt ykman ${AWS_VAULT_PROFILE_USING_MFA} -- aws s3 ls
```

An alternative to manually supplying the prompt driver as a CLI argument to `aws-vault` is setting the
[`mfa_process`](/docs/config#mfa_process) parameter in your `.aws/config` for the profiles that should
use a YubiKey to generate tokens. Example:

(Note: Remember to swap out the name of the OATH account used in `mfa_process` below with the name you gave it during
[YubiKey setup](#setup))

```ini
[profile jon]
mfa_serial = arn:aws:iam::123456789012:mfa/jonsmith
mfa_process = ykman oath accounts code --single arn:aws:iam::123456789012:mfa/jonsmith
```

Further config:

- `AWS_VAULT_PROMPT=ykman`: to avoid specifying `--prompt` each time
- `YKMAN_OATH_CREDENTIAL_NAME`: to use an alternative ykman credential
- `AWS_VAULT_YKMAN_VERSION`: to set the major version of the ykman cli being used. Defaults to "4"
- `YKMAN_OATH_DEVICE_SERIAL`: to set the device serial of a specific Yubikey if you have multiple Yubikeys plugged into
   your computer.
