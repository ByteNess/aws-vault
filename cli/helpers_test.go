package cli

import (
	"log"
	"os"
)

// Examples have no testing.T for t.Setenv and t.TempDir, so they use these.

// setExampleEnv sets environment variables from key-value pairs and returns a
// func that unsets them.
func setExampleEnv(kv ...string) (unset func()) {
	for i := 0; i < len(kv); i += 2 {
		if err := os.Setenv(kv[i], kv[i+1]); err != nil {
			log.Fatal(err)
		}
	}
	return func() {
		for i := 0; i < len(kv); i += 2 {
			_ = os.Unsetenv(kv[i])
		}
	}
}

// exampleConfigFile writes content to a temporary AWS config file and returns
// its path and a func that removes it.
func exampleConfigFile(content string) (path string, remove func()) {
	f, err := os.CreateTemp("", "aws-config")
	if err != nil {
		log.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
	return f.Name(), func() { _ = os.Remove(f.Name()) }
}
