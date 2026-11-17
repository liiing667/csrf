//go:build go1.24

package csrf

import "testing"

// TestGenerateRandomBytesUnavailable documents that the crypto/rand short-read
// failure path cannot be tested on Go 1.24 and later: a broken
// crypto/rand.Reader now terminates the process instead of returning an error
// (see https://go.dev/issue/66821), so replacing rand.Reader with a failing
// reader would crash the whole test binary.
func TestGenerateRandomBytesUnavailable(t *testing.T) {
	t.Skip("crypto/rand failures are fatal on Go 1.24+; see https://go.dev/issue/66821")
}
