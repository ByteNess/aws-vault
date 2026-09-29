// Package prompt asks the user for MFA codes, in the terminal or a GUI dialog.
package prompt

import (
	"fmt"
	"sort"
)

// Func prompts for an MFA code for the given MFA serial and returns it.
type Func func(string) (string, error)

// Methods holds the available prompt methods by name; each platform registers its own.
var Methods = map[string]Func{}

// Available returns the names of the available prompt methods, sorted.
func Available() []string {
	methods := make([]string, 0, len(Methods))
	for k := range Methods {
		methods = append(methods, k)
	}
	sort.Strings(methods)
	return methods
}

// Method returns the prompt method named s, and panics if there is none.
func Method(s string) Func {
	m, ok := Methods[s]
	if !ok {
		panic(fmt.Sprintf("Prompt method %q doesn't exist", s))
	}
	return m
}

func mfaPromptMessage(mfaSerial string) string {
	return fmt.Sprintf("Enter MFA code for %s: ", mfaSerial)
}
