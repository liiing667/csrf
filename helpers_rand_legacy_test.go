//go:build !go1.24
// +build !go1.24

package csrf

import (
	"crypto/rand"
	"io"
	"testing"
)

// shortReader provides a broken implementation of io.Reader for testing.
type shortReader struct{}

func (sr shortReader) Read(p []byte) (int, error) {
	return len(p) % 2, io.ErrUnexpectedEOF
}

// TestGenerateRandomBytes tests the (extremely rare) case that crypto/rand does
// not return the expected number of bytes.
//
// On Go 1.24 and later crypto/rand.Read terminates the program irrecoverably
// when Reader returns an error (see https://go.dev/issue/66821), so swapping
// in a failing reader is no longer a viable test strategy there.
func TestGenerateRandomBytes(t *testing.T) {
	// Pioneered from https://github.com/justinas/nosurf
	original := rand.Reader
	rand.Reader = shortReader{}
	defer func() {
		rand.Reader = original
	}()

	b, err := generateRandomBytes(tokenLength)
	if err == nil {
		t.Fatalf("generateRandomBytes did not report a short read: only read %d bytes", len(b))
	}
}
