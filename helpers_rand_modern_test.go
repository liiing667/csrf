//go:build go1.24
// +build go1.24

package csrf

import "testing"

// TestGenerateRandomBytes verifies that the helper returns the requested number
// of random bytes from the operating system source. The error path cannot be
// exercised on Go 1.24+ because crypto/rand.Read aborts the process when the
// underlying reader fails (see https://go.dev/issue/66821).
func TestGenerateRandomBytes(t *testing.T) {
	b, err := generateRandomBytes(tokenLength)
	if err != nil {
		t.Fatalf("generateRandomBytes returned an unexpected error: %v", err)
	}

	if len(b) != tokenLength {
		t.Fatalf("generateRandomBytes returned %d bytes, want %d", len(b), tokenLength)
	}
}
