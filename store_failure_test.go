//go:build go1.11
// +build go1.11

package csrf

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// errorStoreStub is an ErrorStore that returns a configurable classified
// error from GetError and records whether Save was ever called.
type errorStoreStub struct {
	getErr    error
	token     []byte
	saveCalls int
	saveErr   error
}

func (s *errorStoreStub) Get(_ *http.Request) ([]byte, error) {
	return s.token, s.getErr
}

func (s *errorStoreStub) GetError(_ *http.Request) ([]byte, error) {
	return s.token, s.getErr
}

func (s *errorStoreStub) Save(_ []byte, _ http.ResponseWriter) error {
	s.saveCalls++
	return s.saveErr
}

// legacyStoreStub only implements the legacy store interface. Any error it
// returns must be treated as ErrStoreUnavailable and fail closed.
type legacyStoreStub struct {
	token     []byte
	getErr    error
	saveCalls int
}

func (s *legacyStoreStub) Get(_ *http.Request) ([]byte, error) {
	return s.token, s.getErr
}

func (s *legacyStoreStub) Save(_ []byte, _ http.ResponseWriter) error {
	s.saveCalls++
	return nil
}

// TestStoreNotFoundMintsToken verifies that a missing token (first visit)
// still mints and saves a fresh token instead of failing.
func TestStoreNotFoundMintsToken(t *testing.T) {
	st := &errorStoreStub{getErr: &StoreError{Op: "get", Err: ErrStoreNotFound}}

	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey, setStore(st))(s)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("missing token should mint a new token: got %v want %v",
			rr.Code, http.StatusOK)
	}
	if st.saveCalls != 1 {
		t.Fatalf("fresh token should be saved once: got %d calls want 1", st.saveCalls)
	}
}

// TestStoreDecodeFailsClosed verifies that an HMAC/decode failure rejects the
// request without minting or saving a replacement token.
func TestStoreDecodeFailsClosed(t *testing.T) {
	st := &errorStoreStub{getErr: &StoreError{Op: "get", Err: ErrStoreDecode}}

	var finalErr error
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey, setStore(st), ErrorHandler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			finalErr = FailureReason(r)
			w.WriteHeader(http.StatusForbidden)
		})))(s)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, httptest.NewRequest("POST", "/", nil))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("decode failure should fail closed: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
	if st.saveCalls != 0 {
		t.Fatalf("decode failure must not mint a replacement token: got %d saves",
			st.saveCalls)
	}
	if !errors.Is(finalErr, ErrStoreDecode) {
		t.Fatalf("failure reason should wrap ErrStoreDecode: got %v", finalErr)
	}
}

// TestStoreUnavailableFailsClosed verifies that a backend storage error
// rejects the request instead of degrading into a freshly minted token.
func TestStoreUnavailableFailsClosed(t *testing.T) {
	st := &errorStoreStub{getErr: &StoreError{Op: "get", Err: ErrStoreUnavailable}}

	var finalErr error
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey, setStore(st), ErrorHandler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			finalErr = FailureReason(r)
			w.WriteHeader(http.StatusForbidden)
		})))(s)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("store failure should fail closed: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
	if st.saveCalls != 0 {
		t.Fatalf("store failure must not mint a replacement token: got %d saves",
			st.saveCalls)
	}
	if !errors.Is(finalErr, ErrStoreUnavailable) {
		t.Fatalf("failure reason should wrap ErrStoreUnavailable: got %v", finalErr)
	}
}

// TestLegacyStoreErrorFailsClosed verifies that a store implementing only the
// legacy store interface keeps working, but its errors are conservatively
// classified as unavailable and fail closed (no downgrade, no token refresh).
func TestLegacyStoreErrorFailsClosed(t *testing.T) {
	st := &legacyStoreStub{getErr: errors.New("backend down")}

	var finalErr error
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey, setStore(st), ErrorHandler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			finalErr = FailureReason(r)
			w.WriteHeader(http.StatusForbidden)
		})))(s)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("legacy store error should fail closed: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
	if st.saveCalls != 0 {
		t.Fatalf("legacy store error must not mint a replacement token: got %d saves",
			st.saveCalls)
	}
	if !errors.Is(finalErr, ErrStoreUnavailable) {
		t.Fatalf("legacy store error should map to ErrStoreUnavailable: got %v",
			finalErr)
	}
}

// TestLegacyStoreWithoutErrorMintsToken verifies the migration path: a legacy
// store that returns (token, nil) is used exactly as before.
func TestLegacyStoreWithoutErrorMintsToken(t *testing.T) {
	validToken, err := generateRandomBytes(tokenLength)
	if err != nil {
		t.Fatal(err)
	}
	st := &legacyStoreStub{token: validToken}

	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey, setStore(st))(s)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("legacy store returning a valid token should pass: got %v want %v",
			rr.Code, http.StatusOK)
	}
	if st.saveCalls != 0 {
		t.Fatalf("a valid token must not be re-saved: got %d calls want 0", st.saveCalls)
	}
}

// TestMalformedTokenLengthFailsClosed verifies that a store returning a
// well-decoded but wrong-length token fails closed instead of replacing it.
func TestMalformedTokenLengthFailsClosed(t *testing.T) {
	badToken, err := generateRandomBytes(tokenLength - 1)
	if err != nil {
		t.Fatal(err)
	}
	st := &errorStoreStub{token: badToken}

	var finalErr error
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey, setStore(st), ErrorHandler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			finalErr = FailureReason(r)
			w.WriteHeader(http.StatusForbidden)
		})))(s)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("wrong-length token should fail closed: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
	if st.saveCalls != 0 {
		t.Fatalf("wrong-length token must not be replaced: got %d saves", st.saveCalls)
	}
	if !errors.Is(finalErr, ErrStoreDecode) {
		t.Fatalf("wrong-length token should map to ErrStoreDecode: got %v", finalErr)
	}
}

// TestSaveFailureFailsClosed verifies that a Save error after minting a
// first-visit token is surfaced as ErrStoreUnavailable and rejects the
// request.
func TestSaveFailureFailsClosed(t *testing.T) {
	st := &errorStoreStub{
		getErr:  &StoreError{Op: "get", Err: ErrStoreNotFound},
		saveErr: errors.New("disk full"),
	}

	var finalErr error
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey, setStore(st), ErrorHandler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			finalErr = FailureReason(r)
			w.WriteHeader(http.StatusForbidden)
		})))(s)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("save failure should fail closed: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
	if !errors.Is(finalErr, ErrStoreUnavailable) {
		t.Fatalf("save failure should map to ErrStoreUnavailable: got %v", finalErr)
	}
}

// TestClassifyStoreError covers the sentinel mapping used by the middleware.
func TestClassifyStoreError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"not found", &StoreError{Err: ErrStoreNotFound}, ErrStoreNotFound},
		{"wrapped not found", errors.Join(ErrStoreNotFound, errors.New("x")), ErrStoreNotFound},
		{"decode", &StoreError{Err: ErrStoreDecode}, ErrStoreDecode},
		{"unavailable", &StoreError{Err: ErrStoreUnavailable}, ErrStoreUnavailable},
		{"legacy plain error", errors.New("boom"), ErrStoreUnavailable},
		{"nil-safe unknown", errStub{}, ErrStoreUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyStoreError(tc.err); got != tc.want {
				t.Fatalf("classifyStoreError() = %v want %v", got, tc.want)
			}
		})
	}
}

type errStub struct{}

func (errStub) Error() string { return "stub" }

// TestTamperedCookieNeverRotatesToken is the end-to-end regression test for the
// failure-chain downgrade: when the session cookie fails HMAC validation, the
// middleware must reject the request without writing a replacement cookie,
// even on a safe method where no request token is required.
func TestTamperedCookieNeverRotatesToken(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey)(s)

	// First obtain a genuine cookie.
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	originalCookie := rr.Header().Get("Set-Cookie")
	if originalCookie == "" {
		t.Fatal("expected an initial CSRF cookie")
	}

	// Send only the cookie name/value pair (drop the attributes) with a
	// tampered value. A GET requires no request token, so any rejection comes
	// straight from the store failure policy.
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Cookie", cookieName+"=tampered-cookie-value")

	rr = httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("tampered cookie should fail closed on a safe method: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
	if c := rr.Header().Get("Set-Cookie"); c != "" {
		t.Fatalf("tampered cookie must not trigger a replacement cookie: got %q", c)
	}

	// A genuine first-visit request (no cookie at all) still mints a token.
	rr = httptest.NewRecorder()
	p.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != http.StatusOK || rr.Header().Get("Set-Cookie") == "" {
		t.Fatalf("missing cookie should still mint a fresh token: code=%v cookie=%q",
			rr.Code, rr.Header().Get("Set-Cookie"))
	}
}
