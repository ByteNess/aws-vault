package vault

import (
	"errors"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/byteness/aws-vault/v8/prompt"
)

// Mfa contains options for an MFA device
type Mfa struct {
	MfaSerial     string
	mfaPromptFunc prompt.Func
}

// GetMfaToken returns the MFA token
func (m Mfa) GetMfaToken() (*string, error) {
	if m.mfaPromptFunc != nil {
		token, err := m.mfaPromptFunc(m.MfaSerial)
		return aws.String(token), err
	}

	return nil, errors.New("No prompt found")
}

func NewMfa(config *ProfileConfig) Mfa {
	m := Mfa{
		MfaSerial: config.MfaSerial,
	}
	if config.MfaToken != "" {
		m.mfaPromptFunc = func(_ string) (string, error) { return config.MfaToken, nil }
	} else if config.MfaProcess != "" {
		m.mfaPromptFunc = func(_ string) (string, error) {
			log.Println("Executing mfa_process")
			return ProcessMfaProvider(config.MfaProcess)
		}
	} else {
		m.mfaPromptFunc = prompt.Method(config.MfaPromptMethod)
	}

	return m
}

func ProcessMfaProvider(processCmd string) (string, error) {
	return executeMFACommand(processCmd)
}
