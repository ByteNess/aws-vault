package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	osexec "os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/byteness/aws-vault/v7/iso8601"
	"github.com/byteness/aws-vault/v7/server"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

type ExecCommandInput struct {
	ProfileName      string
	Command          string
	Args             []string
	StartEc2Server   bool
	StartEcsServer   bool
	Lazy             bool
	JSONDeprecated   bool
	Config           vault.ProfileConfig
	SessionDuration  time.Duration
	NoSession        bool
	UseStdout        bool
	ShowHelpMessages bool
	RedactSecrets    bool
}

func (input ExecCommandInput) validate() error {
	if input.StartEc2Server && input.StartEcsServer {
		return fmt.Errorf("Can't use --ec2-server with --ecs-server")
	}
	if input.StartEc2Server && input.JSONDeprecated {
		return fmt.Errorf("Can't use --ec2-server with --json")
	}
	if input.StartEc2Server && input.NoSession {
		return fmt.Errorf("Can't use --ec2-server with --no-session")
	}
	if input.StartEcsServer && input.JSONDeprecated {
		return fmt.Errorf("Can't use --ecs-server with --json")
	}
	if input.StartEcsServer && input.NoSession {
		return fmt.Errorf("Can't use --ecs-server with --no-session")
	}
	if input.StartEcsServer && input.Config.MfaPromptMethod == "terminal" {
		return fmt.Errorf("Can't use --prompt=terminal with --ecs-server. Specify a different prompt driver")
	}
	if input.StartEc2Server && input.Config.MfaPromptMethod == "terminal" {
		return fmt.Errorf("Can't use --prompt=terminal with --ec2-server. Specify a different prompt driver")
	}

	return nil
}

func hasBackgroundServer(input ExecCommandInput) bool {
	return input.StartEcsServer || input.StartEc2Server
}

func ConfigureExecCommand(app *kingpin.Application, a *AwsVault) {
	input := ExecCommandInput{}

	cmd := app.Command("exec", "Execute a command with AWS credentials.")

	cmd.Flag("duration", "Duration of the temporary or assume-role session. Defaults to 1h").
		Short('d').
		DurationVar(&input.SessionDuration)

	cmd.Flag("no-session", "Skip creating STS session with GetSessionToken").
		Short('n').
		BoolVar(&input.NoSession)

	cmd.Flag("region", "The AWS region").
		StringVar(&input.Config.Region)

	cmd.Flag("mfa-token", "The MFA token to use").
		Short('t').
		StringVar(&input.Config.MfaToken)

	cmd.Flag("json", "Output credentials in JSON that can be used by credential_process").
		Short('j').
		Hidden().
		BoolVar(&input.JSONDeprecated)

	cmd.Flag("server", "Alias for --ecs-server").
		Short('s').
		BoolVar(&input.StartEcsServer)

	cmd.Flag("ec2-server", "Run a EC2 metadata server in the background for credentials").
		BoolVar(&input.StartEc2Server)

	cmd.Flag("ecs-server", "Run a ECS credential server in the background for credentials (the SDK or app must support AWS_CONTAINER_CREDENTIALS_FULL_URI)").
		BoolVar(&input.StartEcsServer)

	cmd.Flag("lazy", "When using --ecs-server, lazily fetch credentials").
		BoolVar(&input.Lazy)

	cmd.Flag("stdout", "Print the SSO link to the terminal without automatically opening the browser").
		OverrideDefaultFromEnvar("AWS_VAULT_STDOUT").
		BoolVar(&input.UseStdout)

	cmd.Flag("redact", "Redact AWS credentials from subprocess output").
		BoolVar(&input.RedactSecrets)

	cmd.Arg("profile", "Name of the profile").
		//Required().
		Default(os.Getenv("AWS_PROFILE")).
		HintAction(a.MustGetProfileNames).
		StringVar(&input.ProfileName)

	cmd.Arg("cmd", "Command to execute, defaults to $SHELL").
		StringVar(&input.Command)

	cmd.Arg("args", "Command arguments").
		StringsVar(&input.Args)

	cmd.Action(func(c *kingpin.ParseContext) (err error) {
		input.Config.MfaPromptMethod = a.PromptDriver(hasBackgroundServer(input))
		input.Config.NonChainedGetSessionTokenDuration = input.SessionDuration
		input.Config.AssumeRoleDuration = input.SessionDuration
		input.Config.SSOUseStdout = input.UseStdout
		input.ShowHelpMessages = !a.Debug && input.Command == "" && isATerminal() && os.Getenv("AWS_VAULT_DISABLE_HELP_MESSAGE") != "1"

		f, err := a.AwsConfigFile()
		if err != nil {
			return err
		}
		keyring, err := a.Keyring()
		if err != nil {
			return err
		}

		if input.ProfileName == "" {
			// If no profile provided select from configured AWS profiles
			ProfileName, err := pickAwsProfile(f.ProfileNames())

			if err != nil {
				return fmt.Errorf("unable to select a 'profile'. Try --help: %w", err)
			}

			input.ProfileName = ProfileName
		}

		exitcode := 0
		if input.JSONDeprecated {
			exportCommandInput := ExportCommandInput{
				ProfileName:     input.ProfileName,
				Format:          "json",
				Config:          input.Config,
				SessionDuration: input.SessionDuration,
				NoSession:       input.NoSession,
			}

			err = ExportCommand(exportCommandInput, f, keyring)
		} else {
			// Determine final redaction setting: CLI flag overrides config file
			if input.RedactSecrets {
				input.Config.RedactSecrets = true
			}
			exitcode, err = ExecCommand(input, f, keyring)
		}

		app.FatalIfError(err, "exec")

		// override exit code if not err
		os.Exit(exitcode)

		return nil
	})
}

func ExecCommand(input ExecCommandInput, f *vault.ConfigFile, keyring keyring.Keyring) (exitcode int, err error) {
	if os.Getenv("AWS_VAULT") != "" {
		return 0, fmt.Errorf("running in an existing aws-vault subshell; 'exit' from the subshell or unset AWS_VAULT to force")
	}

	if err := input.validate(); err != nil {
		return 0, err
	}

	config, err := vault.NewConfigLoader(input.Config, f, input.ProfileName).GetProfileConfig(input.ProfileName)
	if err != nil {
		return 0, fmt.Errorf("Error loading config: %w", err)
	}

	credsProvider, err := vault.NewTempCredentialsProvider(config, &vault.CredentialKeyring{Keyring: keyring}, input.NoSession, false)
	if err != nil {
		return 0, fmt.Errorf("Error getting temporary credentials: %w", err)
	}

	subshellHelp := ""
	if input.Command == "" {
		input.Command = getDefaultShell()
		subshellHelp = fmt.Sprintf("Starting subshell %s, use `exit` to exit the subshell", input.Command)
	}

	cmdEnv := createEnv(input.ProfileName, config.Region, config.EndpointURL)

	// Get credentials for redaction if needed
	var credentials aws.Credentials
	if config.RedactSecrets {
		creds, err := credsProvider.Retrieve(context.TODO())
		if err != nil {
			return 0, fmt.Errorf("Failed to get credentials for redaction: %w", err)
		}
		credentials = creds
	}

	if input.StartEc2Server {
		if server.IsProxyRunning() {
			return 0, fmt.Errorf("Another process is already bound to 169.254.169.254:80")
		}

		printHelpMessage("Warning: Starting a local EC2 credential server on 169.254.169.254:80; AWS credentials will be accessible to any process while it is running", input.ShowHelpMessages)
		if err := server.StartEc2EndpointProxyServerProcess(); err != nil {
			return 0, err
		}
		defer server.StopProxy()

		if err = server.StartEc2CredentialsServer(context.TODO(), credsProvider, config.Region); err != nil {
			return 0, fmt.Errorf("Failed to start credential server: %w", err)
		}
		printHelpMessage(subshellHelp, input.ShowHelpMessages)
	} else if input.StartEcsServer {
		printHelpMessage("Starting a local ECS credential server; your app's AWS sdk must support AWS_CONTAINER_CREDENTIALS_FULL_URI.", input.ShowHelpMessages)
		if err = startEcsServerAndSetEnv(credsProvider, config, input.Lazy, &cmdEnv); err != nil {
			return 0, err
		}
		printHelpMessage(subshellHelp, input.ShowHelpMessages)
	} else {
		if err = addCredsToEnv(credsProvider, input.ProfileName, &cmdEnv); err != nil {
			return 0, err
		}
		printHelpMessage(subshellHelp, input.ShowHelpMessages)

		if config.RedactSecrets {
			// When redaction is enabled, we must use runSubProcess to wrap stdout/stderr
			return runSubProcess(input.Command, input.Args, cmdEnv, config.RedactSecrets, credentials)
		} else {
			// When redaction is disabled, try doExecSyscall first for better performance
			err = doExecSyscall(input.Command, input.Args, cmdEnv) // will not return if exec syscall succeeds
			if err != nil {
				log.Println("Error doing execve syscall:", err.Error())
				log.Println("Falling back to running a subprocess")
				return runSubProcess(input.Command, input.Args, cmdEnv, config.RedactSecrets, credentials)
			}
			// If doExecSyscall succeeded, we never reach here (it replaces the process)
		}
	}

	// This should never be reached in the non-redaction case
	return runSubProcess(input.Command, input.Args, cmdEnv, config.RedactSecrets, credentials)
}

func printHelpMessage(helpMsg string, showHelpMessages bool) {
	if helpMsg != "" {
		if showHelpMessages {
			printToStderr(helpMsg)
		} else {
			log.Println(helpMsg)
		}
	}
}

func printToStderr(helpMsg string) {
	fmt.Fprint(os.Stderr, helpMsg, "\n")
}

func createEnv(profileName string, region string, endpointURL string) environ {
	env := environ(os.Environ())
	env.Unset("AWS_ACCESS_KEY_ID")
	env.Unset("AWS_SECRET_ACCESS_KEY")
	env.Unset("AWS_SESSION_TOKEN")
	env.Unset("AWS_SECURITY_TOKEN")
	env.Unset("AWS_CREDENTIAL_FILE")
	env.Unset("AWS_DEFAULT_PROFILE")
	env.Unset("AWS_PROFILE")
	env.Unset("AWS_SDK_LOAD_CONFIG")

	env.Set("AWS_VAULT", profileName)

	if region != "" {
		// AWS_REGION is used by most SDKs. But boto3 (Python SDK) uses AWS_DEFAULT_REGION
		// See https://docs.aws.amazon.com/sdkref/latest/guide/feature-region.html
		log.Printf("Setting subprocess env: AWS_REGION=%s, AWS_DEFAULT_REGION=%s", region, region)
		env.Set("AWS_REGION", region)
		env.Set("AWS_DEFAULT_REGION", region)
	}

	if endpointURL != "" {
		log.Printf("Setting subprocess env: AWS_ENDPOINT_URL=%s", endpointURL)
		env.Set("AWS_ENDPOINT_URL", endpointURL)
	}

	return env
}

func startEcsServerAndSetEnv(credsProvider aws.CredentialsProvider, config *vault.ProfileConfig, lazy bool, cmdEnv *environ) error {
	ecsServer, err := server.NewEcsServer(context.TODO(), credsProvider, config, "", 0, lazy)
	if err != nil {
		return err
	}
	go func() {
		err = ecsServer.Serve()
		if err != http.ErrServerClosed { // ErrServerClosed is a graceful close
			log.Fatalf("ecs server: %s", err.Error())
		}
	}()

	log.Println("Setting subprocess env AWS_CONTAINER_CREDENTIALS_FULL_URI, AWS_CONTAINER_AUTHORIZATION_TOKEN")
	cmdEnv.Set("AWS_CONTAINER_CREDENTIALS_FULL_URI", ecsServer.BaseURL())
	cmdEnv.Set("AWS_CONTAINER_AUTHORIZATION_TOKEN", ecsServer.AuthToken())

	return nil
}

func addCredsToEnv(credsProvider aws.CredentialsProvider, profileName string, cmdEnv *environ) error {
	creds, err := credsProvider.Retrieve(context.TODO())
	if err != nil {
		return fmt.Errorf("Failed to get credentials for %s: %w", profileName, err)
	}

	log.Println("Setting subprocess env: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
	cmdEnv.Set("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	cmdEnv.Set("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)

	if creds.SessionToken != "" {
		log.Println("Setting subprocess env: AWS_SESSION_TOKEN")
		cmdEnv.Set("AWS_SESSION_TOKEN", creds.SessionToken)
	}
	if creds.CanExpire {
		log.Println("Setting subprocess env: AWS_CREDENTIAL_EXPIRATION")
		cmdEnv.Set("AWS_CREDENTIAL_EXPIRATION", iso8601.Format(creds.Expires))
	}

	return nil
}

// environ is a slice of strings representing the environment, in the form "key=value".
type environ []string

// Unset an environment variable by key
func (e *environ) Unset(key string) {
	for i := range *e {
		if strings.HasPrefix((*e)[i], key+"=") {
			(*e)[i] = (*e)[len(*e)-1]
			*e = (*e)[:len(*e)-1]
			break
		}
	}
}

// Set adds an environment variable, replacing any existing ones of the same key
func (e *environ) Set(key, val string) {
	e.Unset(key)
	*e = append(*e, key+"="+val)
}

func getDefaultShell() string {
	command := os.Getenv("SHELL")
	if command == "" {
		if runtime.GOOS == "windows" {
			command = "cmd.exe"
		} else {
			command = "/bin/sh"
		}
	}
	return command
}

func runSubProcess(command string, args []string, env []string, redactSecrets bool, credentials aws.Credentials) (int, error) {
	log.Printf("Starting a subprocess: %s %s", command, strings.Join(args, " "))

	cmd := osexec.Command(command, args...)
	cmd.Stdin = os.Stdin
	cmd.Env = env

	if redactSecrets {
		return runSubProcessWithRedaction(cmd, credentials)
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan)

		if err := cmd.Start(); err != nil {
			return 0, err
		}

		// proxy signals to process
		done := make(chan struct{})
		go func() {
			for {
				select {
				case sig := <-sigChan:
					if cmd.Process != nil {
						_ = cmd.Process.Signal(sig)
					}
				case <-done:
					return
				}
			}
		}()

		if err := cmd.Wait(); err != nil {
			_ = cmd.Process.Signal(os.Kill)
			close(done)
			signal.Stop(sigChan)
			return 0, fmt.Errorf("subprocess exited with error: %w", err)
		}

		close(done)
		signal.Stop(sigChan)
		waitStatus := cmd.ProcessState.Sys().(syscall.WaitStatus)
		return waitStatus.ExitStatus(), nil
	}
}

func getStderrWindowSize(maxCredLen int) int {
	const defaultSize = 256

	if envVal := os.Getenv("AWS_VAULT_STDERR_WINDOW_SIZE"); envVal != "" {
		if size, err := strconv.Atoi(envVal); err == nil {
			if size < 0 {
				log.Printf("Invalid AWS_VAULT_STDERR_WINDOW_SIZE: %d, using default %d", size, defaultSize)
				return defaultSize
			}
			if size > maxCredLen {
				// Cap at maxCredLen - no point going higher
				return maxCredLen
			}
			return size
		}
		log.Printf("Invalid AWS_VAULT_STDERR_WINDOW_SIZE: %s, using default %d", envVal, defaultSize)
	}

	// Ensure we don't exceed maxCredLen
	if defaultSize > maxCredLen {
		return maxCredLen
	}

	return defaultSize
}

func runSubProcessWithRedaction(cmd *osexec.Cmd, credentials aws.Credentials) (int, error) {
	// Create pipes for stdout/stderr
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("Failed to create stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return 0, fmt.Errorf("Failed to create stderr pipe: %w", err)
	}

	// Start the process (fork + exec happens here)
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("Failed to start process: %w", err)
	}

	// Create WaitGroup to wait for output goroutines
	var wg sync.WaitGroup
	wg.Add(2)

	// Calculate max credential length for sliding window
	maxCredLen := maxCredentialLength(credentials)
	stderrWindowSize := getStderrWindowSize(maxCredLen)

	// Handle stdout redaction with sliding window
	go func() {
		defer wg.Done()
		streamWithRedaction(stdoutPipe, os.Stdout, credentials, maxCredLen)
	}()

	// Handle stderr redaction with sliding window
	go func() {
		defer wg.Done()
		streamWithRedaction(stderrPipe, os.Stderr, credentials, stderrWindowSize)
	}()

	// Set up signal forwarding
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-sigChan:
				if cmd.Process != nil {
					cmd.Process.Signal(sig)
				}
			case <-done:
				return
			}
		}
	}()

	// Wait for process to complete
	err = cmd.Wait()
	
	// Clean up signal handler
	close(done)
	signal.Stop(sigChan)
	
	// Wait for output goroutines to finish
	wg.Wait()

	if err != nil {
		if exitErr, ok := err.(*osexec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 0, fmt.Errorf("subprocess exited with error: %w", err)
	}
	
	return 0, nil
}

// maxCredentialLength returns the length of the longest credential
func maxCredentialLength(credentials aws.Credentials) int {
	maxLen := 0
	if len(credentials.AccessKeyID) > maxLen {
		maxLen = len(credentials.AccessKeyID)
	}
	if len(credentials.SecretAccessKey) > maxLen {
		maxLen = len(credentials.SecretAccessKey)
	}
	if len(credentials.SessionToken) > maxLen {
		maxLen = len(credentials.SessionToken)
	}
	
	// Session tokens can be 1000+ chars, cap at reasonable limit
	if maxLen > 2048 {
		maxLen = 2048
	}
	
	return maxLen + 100 // Add safety buffer
}

// streamWithRedaction reads from src, redacts credentials, and writes to dst
// Uses a sliding window to handle credentials split across buffer boundaries
func streamWithRedaction(src io.Reader, dst io.Writer, credentials aws.Credentials, maxCredLen int) {
	const bufSize = 4096
	buf := make([]byte, bufSize)
	overlap := make([]byte, 0, maxCredLen)

	for {
		n, err := src.Read(buf)
		if n > 0 {
			// Combine overlap from previous iteration with new data
			combined := append(overlap, buf[:n]...)
			redacted := redactBytes(combined, credentials)

			// Write everything except the last maxCredLen bytes (keep as overlap)
			if len(redacted) > maxCredLen {
				toWrite := redacted[:len(redacted)-maxCredLen]
				if _, writeErr := dst.Write(toWrite); writeErr != nil {
					log.Printf("Error writing output: %v", writeErr)
				}
				// Keep the last maxCredLen bytes as overlap for next iteration
				overlap = redacted[len(redacted)-maxCredLen:]
			} else {
				// Not enough data yet, keep accumulating
				overlap = redacted
			}
		}

		if err != nil {
			// Flush any remaining overlap
			if len(overlap) > 0 {
				if _, writeErr := dst.Write(overlap); writeErr != nil {
					log.Printf("Error writing final output: %v", writeErr)
				}
			}

			if err != io.EOF {
				log.Printf("Error reading: %v", err)
			}
			break
		}
	}
}

// redactBytes redacts AWS credentials from byte data
func redactBytes(data []byte, credentials aws.Credentials) []byte {
	result := data
	
	// Redact access key ID (exact match)
	if credentials.AccessKeyID != "" {
		result = bytes.ReplaceAll(result, []byte(credentials.AccessKeyID), []byte("<REDACTED>"))
	}
	
	// Redact secret access key (exact match)
	if credentials.SecretAccessKey != "" {
		result = bytes.ReplaceAll(result, []byte(credentials.SecretAccessKey), []byte("<REDACTED>"))
	}
	
	// Redact session token (exact match)
	if credentials.SessionToken != "" {
		result = bytes.ReplaceAll(result, []byte(credentials.SessionToken), []byte("<REDACTED>"))
	}
	
	return result
}

func doExecSyscall(command string, args []string, env []string) error {
	log.Printf("Exec command %s %s", command, strings.Join(args, " "))

	argv0, err := osexec.LookPath(command)
	if err != nil {
		return fmt.Errorf("Couldn't find the executable '%s': %w", command, err)
	}

	log.Printf("Found executable %s", argv0)

	argv := make([]string, 0, 1+len(args))
	argv = append(argv, command)
	argv = append(argv, args...)

	return syscall.Exec(argv0, argv, env)
}
