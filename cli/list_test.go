package cli

import (
	"bytes"
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/keyring"
)

func ExampleListCommand() {
	app := kingpin.New("aws-vault", "")
	awsVault := ConfigureGlobals(app)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})
	ConfigureListCommand(app, awsVault)
	kingpin.MustParse(app.Parse([]string{
		"list", "--credentials",
	}))

	// Output:
	// llamas
}

func TestListRowWriteTo(t *testing.T) {
	tests := []struct {
		name     string
		row      listRow
		expected string
	}{
		{
			name:     "full row",
			row:      listRow{Profile: "admin", Credentials: "admin", Sessions: "sts.AssumeRole:1h0m0s"},
			expected: "admin\tadmin\tsts.AssumeRole:1h0m0s\t\n",
		},
		{
			name:     "empty fields render as dash",
			row:      listRow{Profile: "admin"},
			expected: "admin\t-\t-\t\n",
		},
		{
			name:     "orphan credential",
			row:      listRow{Credentials: "admin"},
			expected: "-\tadmin\t-\t\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			tc.row.writeTo(&buf)
			if got := buf.String(); got != tc.expected {
				t.Errorf("writeTo() = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestListCommandOutputWriteTo(t *testing.T) {
	rows := []listRow{
		{Profile: "admin", Credentials: "admin", Sessions: "sts.AssumeRole:1h0m0s"},
		{Profile: "dev"},
	}
	var buf bytes.Buffer
	listCommandOutput{Rows: rows}.writeTo(&buf)

	want := "Profile\tCredentials\tSessions\t\n" +
		"=======\t===========\t========\t\n" +
		"admin\tadmin\tsts.AssumeRole:1h0m0s\t\n" +
		"dev\t-\t-\t\n"

	if got := buf.String(); got != want {
		t.Errorf("writeTo() = %q, want %q", got, want)
	}
}
