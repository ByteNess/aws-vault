---
title: Managing credentials
weight: 5
---

## Using multiple profiles

In addition to using IAM roles to assume temporary privileges as described in [README.md]({{% relref "/getting-started" %}}#roles-and-mfa), aws-vault can also be used with multiple profiles directly. This allows you to use multiple separate AWS accounts that have no relation to one another, such as work and home.

```shell
# Store AWS credentials for the "home" profile
$ aws-vault add home
Enter Access Key Id: ABDCDEFDASDASF
Enter Secret Key: %

# Execute a command using temporary credentials
$ aws-vault exec home -- aws s3 ls
bucket_1
bucket_2

# store credentials for the "work" profile
$ aws-vault add work
Enter Access Key Id: ABDCDEFDASDASF
Enter Secret Key: %

# Execute a command using temporary credentials
$ aws-vault exec work -- aws s3 ls
another_bucket
```

Here is an example `~/.aws/config` file, to help show the configuration. It defines two AWS accounts: "home" and "work", both of which use MFA. The work account provides two roles, allowing the user to become either profile.

```ini
[default]
region = us-east-1

[profile home]
mfa_serial = arn:aws:iam::111111111111:mfa/home-account

[profile work]
mfa_serial = arn:aws:iam::111111111111:mfa/work-account
role_arn = arn:aws:iam::111111111111:role/ReadOnly

[profile work-admin]
role_arn = arn:aws:iam::111111111111:role/Administrator
source_profile = work
```

## Listing profiles and credentials

You can use the `aws-vault list` command to list out the defined profiles, and any session associated with them.

```shell
$ aws-vault list
Profile                  Credentials              Sessions
=======                  ===========              ========
home                     home
work                     work                     1525456570
work-read-only           work
work-admin               work
```

## Removing credentials

The `aws-vault remove` command can be used to remove credentials. It works similarly to the `aws-vault add` command.

```shell
# Remove AWS credentials for the "work" profile
$ aws-vault remove work
Delete credentials for profile "work"? (y|N) y
Deleted credentials.
```

## Migrating credentials between backends

You can copy stored long-lived credentials from one backend to another:

```shell
aws-vault migrate-backend --from wincred --to winhello
```

To migrate one profile:

```shell
aws-vault migrate-backend --from wincred --to winhello --profile dev
```

By default, migration copies credentials and leaves the source backend unchanged. To delete source credentials after the destination has been written and verified:

```shell
aws-vault migrate-backend --from wincred --to winhello --delete-source
```

Use `--dry-run` to list the credential profiles that would be migrated without reading secret data or writing anything. Use `--overwrite` to replace credentials that already exist in the destination backend.

Note: Even with `--dry-run`, some source backends may prompt for confirmation in order to read the profile list itself.

The command migrates long-lived aws-vault credentials only. It does not migrate cached STS sessions or SSO/OIDC tokens. If the destination backend requires interactive unlock, verification may prompt during migration.

## Rotating credentials

Regularly rotating your access keys is a critical part of credential management. You can do this with the `aws-vault rotate <profile>` command as often as you like. [Restrictions on IAM access]({{% relref "/docs/managing-sessions" %}}#temporary-credentials-limitations-with-sts-iam) using `GetSessionToken` means you will need to have [configured MFA]({{% relref "/docs/mfa" %}}) or use the `--no-session` flag.

The minimal IAM policy required to rotate your own credentials is:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreateAccessKey",
                "iam:DeleteAccessKey",
                "iam:GetUser"
            ],
            "Resource": [
                "arn:aws:iam::*:user/${aws:username}"
            ]
        }
    ]
}
```

> [!TIP]
> If you omit AWS profile name `aws-vault` will ask you to select from the list of configured profiles in AWS config - similar to when logging into AWS Console.
