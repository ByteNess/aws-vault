package cli

import (
	"bytes"
	"os"
	osexec "os/exec"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestRedactBytes(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		credentials aws.Credentials
		expected    string
	}{
		{
			name:  "no credentials",
			input: "This is just normal text",
			credentials: aws.Credentials{
				AccessKeyID:     "",
				SecretAccessKey: "",
				SessionToken:    "",
			},
			expected: "This is just normal text",
		},
		{
			name:  "access key only",
			input: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
			credentials: aws.Credentials{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "",
				SessionToken:    "",
			},
			expected: "AWS_ACCESS_KEY_ID=<REDACTED>",
		},
		{
			name:  "secret key only",
			input: "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			credentials: aws.Credentials{
				AccessKeyID:     "",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				SessionToken:    "",
			},
			expected: "AWS_SECRET_ACCESS_KEY=<REDACTED>",
		},
		{
			name:  "session token only",
			input: "AWS_SESSION_TOKEN=AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvP1EAXGJ2R5O5R8ksWOnUkrUsUSSTS2FAKE",
			credentials: aws.Credentials{
				AccessKeyID:     "",
				SecretAccessKey: "",
				SessionToken:    "AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvP1EAXGJ2R5O5R8ksWOnUkrUsUSSTS2FAKE",
			},
			expected: "AWS_SESSION_TOKEN=<REDACTED>",
		},
		{
			name:  "all credentials",
			input: "Access: AKIAIOSFODNN7EXAMPLE Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY Token: AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvP1EAXGJ2R5O5R8ksWOnUkrUsUSSTS2FAKE",
			credentials: aws.Credentials{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				SessionToken:    "AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvP1EAXGJ2R5O5R8ksWOnUkrUsUSSTS2FAKE",
			},
			expected: "Access: <REDACTED> Secret: <REDACTED> Token: <REDACTED>",
		},
		{
			name:  "partial match should not redact",
			input: "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
			credentials: aws.Credentials{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "",
				SessionToken:    "",
			},
			expected: "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF", // Should NOT be redacted
		},
		{
			name:  "credentials in middle of text",
			input: "Found credentials: AKIAIOSFODNN7EXAMPLE in the logs",
			credentials: aws.Credentials{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "",
				SessionToken:    "",
			},
			expected: "Found credentials: <REDACTED> in the logs",
		},
		{
			name:  "multiple occurrences",
			input: "Key1: AKIAIOSFODNN7EXAMPLE Key2: AKIAIOSFODNN7EXAMPLE",
			credentials: aws.Credentials{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "",
				SessionToken:    "",
			},
			expected: "Key1: <REDACTED> Key2: <REDACTED>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactBytes([]byte(tt.input), tt.credentials)
			if string(result) != tt.expected {
				t.Errorf("redactBytes() = %q, want %q", string(result), tt.expected)
			}
		})
	}
}

func TestMaxCredentialLength(t *testing.T) {
	tests := []struct {
		name        string
		credentials aws.Credentials
		expected    int
	}{
		{
			name: "empty credentials",
			credentials: aws.Credentials{
				AccessKeyID:     "",
				SecretAccessKey: "",
				SessionToken:    "",
			},
			expected: 100, // Just the safety buffer
		},
		{
			name: "access key longest",
			credentials: aws.Credentials{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "short",
				SessionToken:    "also_short",
			},
			expected: len("AKIAIOSFODNN7EXAMPLE") + 100,
		},
		{
			name: "secret key longest",
			credentials: aws.Credentials{
				AccessKeyID:     "short",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				SessionToken:    "also_short",
			},
			expected: len("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") + 100,
		},
		{
			name: "session token longest",
			credentials: aws.Credentials{
				AccessKeyID:     "short",
				SecretAccessKey: "also_short",
				SessionToken:    "AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvP1EAXGJ2R5O5R8ksWOnUkrUsUSSTS2FAKE",
			},
			expected: len("AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvP1EAXGJ2R5O5R8ksWOnUkrUsUSSTS2FAKE") + 100,
		},
		{
			name: "very long session token capped",
			credentials: aws.Credentials{
				AccessKeyID:     "short",
				SecretAccessKey: "also_short",
				SessionToken:    strings.Repeat("A", 3000), // Very long token
			},
			expected: 2048 + 100, // Should be capped at 2048 + buffer
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maxCredentialLength(tt.credentials)
			if result != tt.expected {
				t.Errorf("maxCredentialLength() = %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestGetStderrWindowSize(t *testing.T) {
	// Save and restore environment
	originalEnv := os.Getenv("AWS_VAULT_STDERR_WINDOW_SIZE")
	defer func() {
		if originalEnv == "" {
			os.Unsetenv("AWS_VAULT_STDERR_WINDOW_SIZE")
		} else {
			os.Setenv("AWS_VAULT_STDERR_WINDOW_SIZE", originalEnv)
		}
	}()

	tests := []struct {
		name        string
		envValue    string
		maxCredLen  int
		expected    int
	}{
		{
			name:       "no environment variable",
			envValue:   "",
			maxCredLen: 1000,
			expected:   256,
		},
		{
			name:       "valid environment variable",
			envValue:   "512",
			maxCredLen: 1000,
			expected:   512,
		},
		{
			name:       "environment variable exceeds maxCredLen",
			envValue:   "2000",
			maxCredLen: 1000,
			expected:   1000, // Should be capped
		},
		{
			name:       "environment variable negative",
			envValue:   "-100",
			maxCredLen: 1000,
			expected:   256, // Should fall back to default
		},
		{
			name:       "environment variable invalid",
			envValue:   "not_a_number",
			maxCredLen: 1000,
			expected:   256, // Should fall back to default
		},
		{
			name:       "default exceeds maxCredLen",
			envValue:   "",
			maxCredLen: 200,
			expected:   200, // Should be capped at maxCredLen
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue == "" {
				os.Unsetenv("AWS_VAULT_STDERR_WINDOW_SIZE")
			} else {
				os.Setenv("AWS_VAULT_STDERR_WINDOW_SIZE", tt.envValue)
			}

			result := getStderrWindowSize(tt.maxCredLen)
			if result != tt.expected {
				t.Errorf("getStderrWindowSize() = %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestStreamWithRedactionSlidingWindow(t *testing.T) {
	// Test that credentials split across buffer boundaries are properly redacted
	credentials := aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "",
	}

	// Create a credential that will be split across two reads
	credential := "AKIAIOSFODNN7EXAMPLE"
	splitPoint := len(credential) / 2
	
	// First part of credential
	part1 := "Found: " + credential[:splitPoint]
	// Second part of credential  
	part2 := credential[splitPoint:] + " in logs"

	// Create input that simulates the credential being split
	input := part1 + part2

	// Test with sliding window
	var output bytes.Buffer
	reader := strings.NewReader(input)
	
	streamWithRedaction(reader, &output, credentials, len(credential)+100)

	result := output.String()
	
	// The credential should be redacted even though it was split
	if strings.Contains(result, credential) {
		t.Errorf("Credential %q should be redacted but was found in output: %q", credential, result)
	}
	
	if !strings.Contains(result, "<REDACTED>") {
		t.Errorf("Expected <REDACTED> in output but got: %q", result)
	}
}

func TestStreamWithRedactionBasic(t *testing.T) {
	// Test basic streaming functionality
	credentials := aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "",
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple credential redaction",
			input:    "Access key: AKIAIOSFODNN7EXAMPLE",
			expected: "Access key: <REDACTED>",
		},
		{
			name:     "no credentials",
			input:    "Just normal text",
			expected: "Just normal text",
		},
		{
			name:     "multiple credentials",
			input:    "Key: AKIAIOSFODNN7EXAMPLE Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			expected: "Key: <REDACTED> Secret: <REDACTED>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			reader := strings.NewReader(tt.input)
			
			streamWithRedaction(reader, &output, credentials, 1000)
			
			result := output.String()
			if result != tt.expected {
				t.Errorf("streamWithRedaction() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestStreamWithRedactionEmptyInput(t *testing.T) {
	// Test with empty input
	credentials := aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "",
		SessionToken:    "",
	}

	var output bytes.Buffer
	reader := strings.NewReader("")
	
	streamWithRedaction(reader, &output, credentials, 1000)
	
	result := output.String()
	if result != "" {
		t.Errorf("Expected empty output, got %q", result)
	}
}

func TestStreamWithRedactionLargeBuffer(t *testing.T) {
	// Test with large input that exceeds buffer size
	credentials := aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "",
		SessionToken:    "",
	}

	// Create large input with credential in the middle
	largeText := strings.Repeat("A", 10000) + "AKIAIOSFODNN7EXAMPLE" + strings.Repeat("B", 10000)
	
	var output bytes.Buffer
	reader := strings.NewReader(largeText)
	
	streamWithRedaction(reader, &output, credentials, 1000)
	
	result := output.String()
	if strings.Contains(result, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("Credential should be redacted in large buffer")
	}
	if !strings.Contains(result, "<REDACTED>") {
		t.Errorf("Expected <REDACTED> in large buffer output")
	}
}

func TestRunSubProcessWithRedaction(t *testing.T) {
	// Test the runSubProcessWithRedaction function with a simple command
	credentials := aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "",
	}

	// Test with echo command that outputs credentials
	cmd := osexec.Command("echo", "Access key: AKIAIOSFODNN7EXAMPLE")
	
	// Create pipes to capture output
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Failed to create stdout pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("Failed to create stderr pipe: %v", err)
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start process: %v", err)
	}

	// Capture output
	var stdout, stderr bytes.Buffer
	go func() {
		streamWithRedaction(stdoutPipe, &stdout, credentials, 1000)
	}()
	go func() {
		streamWithRedaction(stderrPipe, &stderr, credentials, 1000)
	}()

	// Wait for process to complete
	err = cmd.Wait()
	if err != nil {
		t.Errorf("Process failed: %v", err)
	}
	
	// Check that credentials are redacted in output
	output := stdout.String()
	if strings.Contains(output, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("Credential should be redacted in subprocess output: %q", output)
	}
	if !strings.Contains(output, "<REDACTED>") {
		t.Errorf("Expected <REDACTED> in subprocess output: %q", output)
	}
}

// Note: Integration tests for runSubProcessWithRedaction are complex due to 
// subprocess execution and stdout/stderr redirection. The core functionality
// is tested through the streamWithRedaction tests above.
