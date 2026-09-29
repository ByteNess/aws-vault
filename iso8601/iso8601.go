// Package iso8601 formats times in the ISO 8601 layout AWS uses.
package iso8601

import "time"

// Format outputs an ISO-8601 datetime string from the given time,
// in a format compatible with all of the AWS SDKs
func Format(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
