//go:build !go1.11
// +build !go1.11

// file for compatibility with go versions prior to 1.11

package csrf

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/securecookie"
)

// Check store implementations
var _ store = &cookieStore{}

// brokenSaveStore is a CSRF store that cannot, well, save.
type brokenSaveStore struct {
	store
}

func (bs *brokenSaveStore) Get(*http.Request) ([]byte, error) {
	// Report a missing token so the middleware mints a fresh one and
	// progresses to our Save method.
	return nil, &StoreError{Op: "get", Err: ErrStoreNotFound}
}

func (bs *brokenSaveStore) Save(realToken []byte, w http.ResponseWriter) error {
	return errors.New("test error")
}

// Tests for failure if the middleware can't save to the Store.
func TestStoreCannotSave(t *testing.T) {
	s := http.NewServeMux()
	bs := &brokenSaveStore{}
	s.HandleFunc("/", testHandler)
	p := Protect(testKey, setStore(bs))(s)

	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("broken store did not set an error status: got %v want %v",
			rr.Code, http.StatusForbidden)
	}

	if c := rr.Header().Get("Set-Cookie"); c != "" {
		t.Fatalf("broken store incorrectly set a cookie: got %v want %v",
			c, "")
	}

}

// TestCookieDecode tests that an invalid cookie store returns a decoding error.
func TestCookieDecode(t *testing.T) {
	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	var age = 3600

	// Test with a nil hash key
	sc := securecookie.New(nil, nil)
	sc.MaxAge(age)
	st := &cookieStore{cookieName, age, true, true, "", "", sc, SameSiteDefaultMode}

	// Set a fake cookie value so r.Cookie passes.
	r.Header.Set("Cookie", fmt.Sprintf("%s=%s", cookieName, "notacookie"))

	_, err = st.Get(r)
	if err == nil {
		t.Fatal("cookiestore did not report an invalid hashkey on decode")
	}
}

// TestCookieGetErrorClassifications verifies the cookieStore distinguishes the
// three store failure classes required for fail-closed handling.
func TestCookieGetErrorClassifications(t *testing.T) {
	var age = 3600
	sc := securecookie.New(testKey, nil)
	sc.MaxAge(age)
	st := &cookieStore{cookieName, age, true, true, "", "", sc, SameSiteDefaultMode}

	t.Run("missing cookie is not found", func(t *testing.T) {
		r, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			t.Fatal(err)
		}

		_, err = st.GetError(r)
		if !errors.Is(err, ErrStoreNotFound) {
			t.Fatalf("missing cookie should map to ErrStoreNotFound: got %v", err)
		}
	})

	t.Run("tampered cookie is decode failure", func(t *testing.T) {
		r, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Cookie", fmt.Sprintf("%s=%s", cookieName, "not-a-valid-cookie"))

		_, err = st.GetError(r)
		if !errors.Is(err, ErrStoreDecode) {
			t.Fatalf("tampered cookie should map to ErrStoreDecode: got %v", err)
		}
	})

	t.Run("valid cookie returns the token", func(t *testing.T) {
		realToken, err := generateRandomBytes(tokenLength)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		if err := st.Save(realToken, rr); err != nil {
			t.Fatal(err)
		}

		r, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Cookie", rr.Header().Get("Set-Cookie"))

		got, err := st.GetError(r)
		if err != nil {
			t.Fatalf("valid cookie should decode without error: got %v", err)
		}
		if string(got) != string(realToken) {
			t.Fatalf("decoded token mismatch: got %v want %v", got, realToken)
		}
	})
}

// TestCookieEncode tests that an invalid cookie store returns an encoding error.
func TestCookieEncode(t *testing.T) {
	var age = 3600

	// Test with a nil hash key
	sc := securecookie.New(nil, nil)
	sc.MaxAge(age)
	st := &cookieStore{cookieName, age, true, true, "", "", sc, SameSiteDefaultMode}

	rr := httptest.NewRecorder()

	err := st.Save(nil, rr)
	if err == nil {
		t.Fatal("cookiestore did not report an invalid hashkey on encode")
	}
}

// TestMaxAgeZero tests that setting MaxAge(0) does not set the Expires
// attribute on the cookie.
func TestMaxAgeZero(t *testing.T) {
	var age = 0

	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)

	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	p := Protect(testKey, MaxAge(age))(s)
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusOK)
	}

	if rr.Header().Get("Set-Cookie") == "" {
		t.Fatalf("cookie not set: got %q", rr.Header().Get("Set-Cookie"))
	}

	cookie := rr.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "HttpOnly") || strings.Contains(cookie, "Expires") {
		t.Fatalf("cookie incorrectly has the Expires attribute set: got %q", cookie)
	}
}

// TestSameSizeSet tests that setting SameSite Option does not set the SameSite
// attribute on the cookie in legacy systems.
func TestSameSizeSet(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)

	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	p := Protect(testKey, SameSite(SameSiteStrictMode))(s)
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusOK)
	}

	if rr.Header().Get("Set-Cookie") == "" {
		t.Fatalf("cookie not set: got %q", rr.Header().Get("Set-Cookie"))
	}

	cookie := rr.Header().Get("Set-Cookie")
	if strings.Contains(cookie, "SameSite") {
		t.Fatalf("cookie incorrectly has the SameSite attribute set: got %q", cookie)
	}
}
