---
title: Managing Sessions
weight: 6
---

## Executing a command

Running `aws-vault exec` will run a command with AWS credentials.

When using exec, you may find it useful to use the builtin `--` feature in bash, zsh and other POSIX shells. For example
```shell
aws-vault exec myprofile -- aws s3 ls
```
Using `--` signifies the end of the `aws-vault` options, and allows the shell autocomplete to kick in and offer autocompletions for the proceeding command.

If you use `exec` without specifying a command, AWS Vault will create a new interactive subshell. Note that when creating an interactive subshell, bash, zsh and other POSIX shells will execute the `~/.bashrc` or `~/.zshrc` file. If you have local variables, functions or aliases (for example your `PS1` prompt), ensure that they are defined in the rc file so they get executed when the subshell begins.

> [!TIP]
> If you omit AWS profile name `aws-vault` will ask you to select from the list of configured profiles in AWS config - similar to when logging into AWS Console.
> This only works when spawning a new shell and not when running commands using `--` !

## Logging into AWS Console

You can use the `aws-vault login` command to open a browser window and login to AWS Console for a given profile/account:
```shell
$ aws-vault login myprofile
```

> [!NOTE]
> When using multi-session support in AWS Management Console you might need to avoid using auto-logout using `--auto-logout` or `-a`.
> Otherwise URL redirect won't work and you'll end up with HTTP/400 response.

If you have credentials already available in your environment, `aws-vault` will use these credentials to sign you in to the AWS console.

```shell
$ export AWS_ACCESS_KEY_ID=%%%
$ export AWS_SECRET_ACCESS_KEY=%%%
$ export AWS_SESSION_TOKEN=%%%
$ aws-vault login
```

> [!TIP]
> If you omit AWS profile name and don't have any credentials already available in your environment, `aws-vault` will ask you to select from the list of configured profiles in AWS config.

```shell
? Choose AWS profile:  [Use arrows to move, type to filter]
> default
  work
  test
  sandbox
```

## Removing stored sessions

If you want to remove sessions managed by `aws-vault` before they expire, you can do this with `aws-vault clear` command.

You can also specify a profile to remove sessions for this profile only.
```shell
aws-vault clear [profile]
```

## Using --no-session

AWS Vault will typically create temporary credentials using a combination of `GetSessionToken` and `AssumeRole`, depending on the config. The `GetSessionToken` call is made with MFA if available, and the resulting session is cached in the backend vault and can be used to assume roles from different profiles without further MFA prompts.

If you wish to skip the `GetSessionToken` call, you can use the `--no-session` flag.

However, consider that if you use `--no-session` with a profile using IAM credentials and NO `role_arn`, then your IAM credentials will be directly exposed to the terminal/application you are running. This is the opposite of what you are normally trying to achieve by using AWS Vault. You can easily witness that by doing
```shell
aws-vault exec <iam_user_profile> -- env | grep AWS
```
You'll see an `AWS_ACCESS_KEY_ID` of the form `ASIAxxxxxx` which is a temporary one. Doing
```shell
aws-vault exec <iam_user_profile> --no-session -- env | grep AWS
```
You'll see your IAM user `AWS_ACCESS_KEY_ID` of the form `AKIAxxxxx` directly exposed, as well as the corresponding `AWS_SECRET_KEY_ID`.


## Session duration

If you try to [assume a role](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html) from a temporary session or another role, AWS considers that as [role chaining](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html#iam-term-role-chaining) and limits your ability to assume the target role to 1h. Trying to use a duration longer than 1h may result in an error:
```
aws-vault: error: Failed to get credentials for default: ValidationError: The requested DurationSeconds exceeds the MaxSessionDuration set for this role.
        status code: 400, request id: aa58fa50-4a5e-11e9-9566-293ea5c350ee
```

For that reason, when role chaining is in effect AWS Vault keeps the source profile's `GetSessionToken` session at the duration you requested (up to AWS's 36h maximum for IAM user MFA sessions), and silently caps the chained `AssumeRole` calls to AWS's 1h limit (logged as `capping AssumeRole duration ... for role chaining`).

## Using `--server`

There may be scenarios where you'd like to assume a role for a long length of time, or perhaps when using a tool where using temporary sessions on demand is preferable. For example, when using a tool like [Terraform](https://www.terraform.io/), you need to have AWS credentials available to the application for the entire duration of the infrastructure change.

AWS Vault can run a background server to imitate the metadata endpoint that you would have on an EC2 or ECS instance. When your application uses the AWS SDK to locate credentials, it will automatically connect to this server that will issue a new set of temporary credentials (using the same profile as the one the server was started with). This server will continue to generate temporary credentials any time the application requests it.

### `--ec2-server`

This approach has the major security drawback that while this `aws-vault` server runs, any application wanting to connect to AWS will be able to do so, using the profile the server was started with. Thanks to `aws-vault`, the credentials are not exposed, but the ability to use them to connect to AWS is!

To use `--ec2-server`, AWS Vault needs root/administrator privileges in order to bind to the privileged port. AWS Vault runs a minimal proxy as the root user, proxying through to the real aws-vault instance.

### `--ecs-server`

The ECS Credential provider binds to a random, ephemeral port and requires an authorization token, which offers the following advantages over the EC2 Metadata provider:
 1. Does not require root/administrator privileges
 2. Allows multiple providers simultaneously for discrete processes
 3. Mitigates the security issues that accompany the EC2 Metadata Service because the address is not well-known and the authorization token is only exposed to the subprocess via environment variables

However, this will only work with the AWS SDKs [that support `AWS_CONTAINER_CREDENTIALS_FULL_URI`](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html).

The ECS server also responds to requests on `/role-arn/YOUR_ROLE_ARN` with the role credentials, making it usable with  `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` when combined with a reverse proxy (see the Docker section below).

## Temporary credentials limitations with STS, IAM

When using temporary credentials you are restricted from using some STS and IAM APIs (see [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_request.html#stsapi_comparison)). The restriction is enforced with `InvalidClientTokenId` error response.

```shell
$ aws-vault exec <iam_user_profile> -- aws iam get-user
An error occurred (InvalidClientTokenId) when calling the GetUser operation: The security token included in the request is invalid
```

For restricted IAM operation you can add MFA to the IAM User and update your ~/.aws/config file with [MFA configuration]({{% relref "/docs/mfa" %}}). Alternately you may avoid the temporary session entirely by using `--no-session`.
