//go:build go1.11
// +build go1.11

package csrf

import (
	"errors"
	"net/http"
)

var (
	// ErrStoreNotFound is returned by a store when no CSRF token has been
	// issued for the request yet (e.g. the named cookie is absent). The
	// middleware treats this as a first-visit condition: it mints a new
	// token and saves it to the store.
	ErrStoreNotFound = errors.New("CSRF token not found in store")
	// ErrStoreDecode is returned by a store when a token is present but cannot
	// be authenticated or decoded (e.g. an HMAC failure on a tampered cookie).
	// The middleware fails closed: no replacement token is generated and the
	// request is rejected with a 403 response.
	ErrStoreDecode = errors.New("CSRF token in store failed validation")
	// ErrStoreUnavailable is returned by a store when the backing storage
	// cannot be reached or otherwise fails. The middleware fails closed rather
	// than degrading, so a backend outage can never be turned into a CSRF
	// bypass by an attacker.
	ErrStoreUnavailable = errors.New("CSRF token store unavailable")
)

// StoreError describes why a store failed to return a CSRF token. Stores
// return a *StoreError (or an error wrapping one of the package-level store
// sentinels) so the middleware can apply a distinct strategy to each failure
// class instead of conflating a missing token with a corrupt token or a
// broken backend.
type StoreError struct {
	// Op is the store operation that failed, typically "get".
	Op string
	// Err is one of ErrStoreNotFound, ErrStoreDecode or ErrStoreUnavailable.
	Err error
	// Cause is the underlying store error, if any.
	Cause error
}

func (e *StoreError) Error() string {
	if e.Cause == nil {
		return errorPrefix + e.Op + ": " + e.Err.Error()
	}
	return errorPrefix + e.Op + ": " + e.Err.Error() + ": " + e.Cause.Error()
}

func (e *StoreError) Unwrap() error {
	return e.Err
}

// ErrorStore is implemented by stores that classify their Get errors. It is
// the migration path away from the plain store interface: implementations
// return a *StoreError so the middleware can distinguish a missing token
// (ErrStoreNotFound) from an authentication failure (ErrStoreDecode) and a
// storage backend failure (ErrStoreUnavailable).
//
// Stores that only implement the legacy store interface keep working: their
// errors are conservatively classified as ErrStoreUnavailable, which fails
// closed.
type ErrorStore interface {
	store
	// GetError behaves like store.Get but guarantees the returned error (when
	// non-nil) wraps one of ErrStoreNotFound, ErrStoreDecode or
	// ErrStoreUnavailable.
	GetError(*http.Request) ([]byte, error)
}

// classifyStoreError maps a store.Get error onto one of the three store
// failure classes. Explicit classifications from an ErrorStore are honored;
// errors from legacy stores fail closed as ErrStoreUnavailable.
func classifyStoreError(err error) error {
	switch {
	case errors.Is(err, ErrStoreNotFound):
		return ErrStoreNotFound
	case errors.Is(err, ErrStoreDecode):
		return ErrStoreDecode
	default:
		return ErrStoreUnavailable
	}
}
