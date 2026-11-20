package csrf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var testKey = []byte("keep-it-secret-keep-it-safe-----")
var testHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

// TestProtect is a high-level test to make sure the middleware returns the
// wrapped handler with a 200 OK status.
func TestProtect(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)

	r := createRequest("GET", "/", false)

	rr := httptest.NewRecorder()
	p := Protect(testKey)(s)
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusOK)
	}

	if rr.Header().Get("Set-Cookie") == "" {
		t.Fatalf("cookie not set: got %q", rr.Header().Get("Set-Cookie"))
	}

	cookie := rr.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie,
		"Secure") {
		t.Fatalf("cookie does not default to Secure & HttpOnly: got %v", cookie)
	}
}

// TestCookieOptions is a test to make sure the middleware correctly sets cookie options
func TestCookieOptions(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)

	r := createRequest("GET", "/", false)

	rr := httptest.NewRecorder()
	p := Protect(testKey, CookieName("nameoverride"), Secure(false), HttpOnly(false), Path("/pathoverride"), Domain("domainoverride"), MaxAge(173))(s)
	p.ServeHTTP(rr, r)

	if rr.Header().Get("Set-Cookie") == "" {
		t.Fatalf("cookie not set: got %q", rr.Header().Get("Set-Cookie"))
	}

	cookie := rr.Header().Get("Set-Cookie")
	if strings.Contains(cookie, "HttpOnly") {
		t.Fatalf("cookie does not respect HttpOnly option: got %v do not want HttpOnly", cookie)
	}
	if strings.Contains(cookie, "Secure") {
		t.Fatalf("cookie does not respect Secure option: got %v do not want Secure", cookie)
	}
	if !strings.Contains(cookie, "nameoverride=") {
		t.Fatalf("cookie does not respect CookieName option: got %v want %v", cookie, "nameoverride=")
	}
	if !strings.Contains(cookie, "Domain=domainoverride") {
		t.Fatalf("cookie does not respect Domain option: got %v want %v", cookie, "Domain=domainoverride")
	}
	if !strings.Contains(cookie, "Max-Age=173") {
		t.Fatalf("cookie does not respect MaxAge option: got %v want %v", cookie, "Max-Age=173")
	}
}

// Test that idempotent methods return a 200 OK status and that non-idempotent
// methods return a 403 Forbidden status when a CSRF cookie is not present.
func TestMethods(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey)(s)

	// Test idempontent ("safe") methods
	for _, method := range safeMethods {
		r := createRequest(method, "/", false)

		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, r)

		if rr.Code != http.StatusOK {
			t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
				rr.Code, http.StatusOK)
		}

		if rr.Header().Get("Set-Cookie") == "" {
			t.Fatalf("cookie not set: got %q", rr.Header().Get("Set-Cookie"))
		}
	}

	// Test non-idempotent methods (should return a 403 without a cookie set)
	nonIdempotent := []string{"POST", "PUT", "DELETE", "PATCH"}
	for _, method := range nonIdempotent {
		r := createRequest(method, "/", false)

		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, r)

		if rr.Code != http.StatusForbidden {
			t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
				rr.Code, http.StatusOK)
		}

		// A rejected request must not be issued a fresh, reusable token.
		if rr.Header().Get("Set-Cookie") != "" {
			t.Fatalf("rejected response must not set a cookie: got %q",
				rr.Header().Get("Set-Cookie"))
		}

		// Rejections share the identity cache boundary of successful
		// responses and must never be stored by a cache.
		if rr.Header().Get("Vary") != "Cookie" {
			t.Fatalf("vary header not set on rejection: got %q want %q",
				rr.Header().Get("Vary"), "Cookie")
		}

		if rr.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("rejected response must not be cacheable: got Cache-Control %q want %q",
				rr.Header().Get("Cache-Control"), "no-store")
		}
	}
}

// Tests for failure if the cookie containing the session does not exist on a
// POST request.
func TestNoCookie(t *testing.T) {
	s := http.NewServeMux()
	p := Protect(testKey)(s)

	// POST the token back in the header.
	r := createRequest("POST", "/", false)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("middleware failed to reject a non-existent cookie: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
}

// TestBadCookie tests for failure when a cookie header is modified (malformed).
func TestBadCookie(t *testing.T) {
	s := http.NewServeMux()
	p := Protect(testKey)(s)

	var token string
	s.Handle("/", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))

	// Obtain a CSRF cookie via a GET request.
	r := createRequest("GET", "/", false)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	// POST the token back in the header.
	r = createRequest("POST", "/", false)

	// Replace the cookie prefix
	badHeader := strings.Replace(cookieName+"=", rr.Header().Get("Set-Cookie"), "_badCookie", -1)
	r.Header.Set("Cookie", badHeader)
	r.Header.Set("X-CSRF-Token", token)
	r.Header.Set("Referer", "http://www.gorillatoolkit.org/")

	rr = httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("middleware failed to reject a bad cookie: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
}

// Responses should set a "Vary: Cookie" header to protect client/proxy caching.
func TestVaryHeader(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey)(s)

	r := createRequest("GET", "/", true)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusOK)
	}

	if rr.Header().Get("Vary") != "Cookie" {
		t.Fatalf("vary header not set: got %q want %q", rr.Header().Get("Vary"), "Cookie")
	}
}

// TestNoReferer checks that HTTPS requests with no Referer header fail.
func TestNoReferer(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey)(s)

	r := createRequest("POST", "https://golang.org/", true)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("middleware failed reject an empty Referer header: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
}

// TestBadReferer checks that HTTPS requests with a Referer that does not
// match the request URL correctly fail CSRF validation.
func TestBadReferer(t *testing.T) {
	s := http.NewServeMux()
	p := Protect(testKey)(s)

	var token string
	s.Handle("/", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))

	// Obtain a CSRF cookie via a GET request.
	r := createRequest("GET", "/", true)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	// POST the token back in the header.
	r = createRequest("POST", "/", true)
	setCookie(rr, r)
	r.Header.Set("X-CSRF-Token", token)

	// Set a non-matching Referer header.
	r.Header.Set("Referer", "http://golang.org/")

	rr = httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("middleware failed reject a non-matching Referer header: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
}

// TestTrustedReferer checks that HTTPS requests with a Referer that does not
// match the request URL correctly but is a trusted origin pass CSRF validation.
func TestTrustedReferer(t *testing.T) {

	testTable := []struct {
		trustedOrigin []string
		shouldPass    bool
	}{
		{[]string{"golang.org"}, true},
		{[]string{"api.example.com", "golang.org"}, true},
		{[]string{"http://golang.org"}, false},
		{[]string{"https://golang.org"}, false},
		{[]string{"http://example.com"}, false},
		{[]string{"example.com"}, false},
	}

	for _, item := range testTable {
		t.Run(fmt.Sprintf("TrustedOrigin: %v", item.trustedOrigin), func(t *testing.T) {

			s := http.NewServeMux()

			p := Protect(testKey, TrustedOrigins(item.trustedOrigin))(s)

			var token string
			s.Handle("/", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				token = Token(r)
			}))

			// Obtain a CSRF cookie via a GET request.
			r := createRequest("GET", "/", true)

			rr := httptest.NewRecorder()
			p.ServeHTTP(rr, r)

			// POST the token back in the header.
			r = createRequest("POST", "/", true)

			setCookie(rr, r)
			r.Header.Set("X-CSRF-Token", token)

			// Set a non-matching Referer header.
			r.Header.Set("Referer", "https://golang.org/")

			rr = httptest.NewRecorder()
			p.ServeHTTP(rr, r)

			if item.shouldPass {
				if rr.Code != http.StatusOK {
					t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
						rr.Code, http.StatusOK)
				}
			} else {
				if rr.Code != http.StatusForbidden {
					t.Fatalf("middleware failed reject a non-matching Referer header: got %v want %v",
						rr.Code, http.StatusForbidden)
				}
			}
		})
	}
}

// Requests with a valid Referer should pass.
func TestWithReferer(t *testing.T) {
	s := http.NewServeMux()
	p := Protect(testKey)(s)

	var token string
	s.Handle("/", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))

	// Obtain a CSRF cookie via a GET request.
	r := createRequest("GET", "/", true)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	// POST the token back in the header.
	r = createRequest("POST", "/", true)

	setCookie(rr, r)
	r.Header.Set("X-CSRF-Token", token)
	r.Header.Set("Referer", "https://www.gorillatoolkit.org/")

	rr = httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusOK)
	}
}

// Requests without a token should fail with ErrNoToken.
func TestNoTokenProvided(t *testing.T) {
	var finalErr error

	s := http.NewServeMux()
	p := Protect(testKey, ErrorHandler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		finalErr = FailureReason(r)
	})))(s)

	var token string
	s.Handle("/", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))
	// Obtain a CSRF cookie via a GET request.
	r := createRequest("GET", "/", true)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	// POST the token back in the header.
	r = createRequest("POST", "/", true)

	setCookie(rr, r)
	// By accident we use the wrong header name for the token...
	r.Header.Set("X-CSRF-nekot", token)
	r.Header.Set("Referer", "https://www.gorillatoolkit.org/")

	rr = httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if finalErr != nil && finalErr != ErrNoToken {
		t.Fatalf("middleware failed to return correct error: got '%v' want '%v'", finalErr, ErrNoToken)
	}
}

func setCookie(rr *httptest.ResponseRecorder, r *http.Request) {
	r.Header.Set("Cookie", rr.Header().Get("Set-Cookie"))
}

func TestProtectScenarios(t *testing.T) {
	tests := []struct {
		name                 string
		safeMethod           bool
		originUntrusted      bool
		originHTTP           bool
		originTrusted        bool
		secureRequest        bool
		refererTrusted       bool
		refererUntrusted     bool
		refererHTTPDowngrade bool
		refererRelative      bool
		tokenValid           bool
		tokenInvalid         bool
		want                 bool
	}{
		{
			name:       "safe method pass",
			safeMethod: true,
			want:       true,
		},
		{
			name:       "cleartext POST with trusted origin & valid token pass",
			originHTTP: true,
			tokenValid: true,
			want:       true,
		},
		{
			name:            "cleartext POST with untrusted origin reject",
			originUntrusted: true,
			tokenValid:      true,
		},
		{
			name:       "cleartext POST with HTTP origin & invalid token reject",
			originHTTP: true,
		},
		{
			name:       "cleartext POST without origin with valid token pass",
			tokenValid: true,
			want:       true,
		},
		{
			name: "cleartext POST without origin with invalid token reject",
		},
		{
			name:          "TLS POST with HTTP origin & no referer & valid token reject",
			tokenValid:    true,
			secureRequest: true,
			originHTTP:    true,
		},
		{
			name:          "TLS POST without origin and without referer reject",
			secureRequest: true,
			tokenValid:    true,
		},
		{
			name:             "TLS POST without origin with untrusted referer reject",
			secureRequest:    true,
			refererUntrusted: true,
			tokenValid:       true,
		},
		{
			name:           "TLS POST without origin with trusted referer & valid token pass",
			secureRequest:  true,
			refererTrusted: true,
			tokenValid:     true,
			want:           true,
		},
		{
			name:                 "TLS POST without origin from _cleartext_ same domain referer with valid token reject",
			secureRequest:        true,
			refererHTTPDowngrade: true,
			tokenValid:           true,
		},
		{
			name:            "TLS POST without origin from relative referer with valid token pass",
			secureRequest:   true,
			refererRelative: true,
			tokenValid:      true,
			want:            true,
		},
		{
			name:            "TLS POST without origin from relative referer with invalid token reject",
			secureRequest:   true,
			refererRelative: true,
			tokenInvalid:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var token string
			var flag bool
			mux := http.NewServeMux()
			mux.Handle("/", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				token = Token(r)
			}))
			mux.Handle("/submit", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				flag = true
			}))
			p := Protect(testKey)(mux)

			// Obtain a CSRF cookie via a GET request.
			r := createRequest("GET", "/", tt.secureRequest)
			rr := httptest.NewRecorder()
			p.ServeHTTP(rr, r)

			r = createRequest("POST", "/submit", tt.secureRequest)
			if tt.safeMethod {
				r = createRequest("GET", "/submit", tt.secureRequest)
			}

			// Set the Origin header
			switch {
			case tt.originUntrusted:
				r.Header.Set("Origin", "http://www.untrusted-origin.org")
			case tt.originTrusted:
				r.Header.Set("Origin", "https://www.gorillatoolkit.org")
			case tt.originHTTP:
				r.Header.Set("Origin", "http://www.gorillatoolkit.org")
			}

			// Set the Referer header
			switch {
			case tt.refererTrusted:
				p = Protect(testKey, TrustedOrigins([]string{"external-trusted-origin.test"}))(mux)
				r.Header.Set("Referer", "https://external-trusted-origin.test/foobar")
			case tt.refererUntrusted:
				r.Header.Set("Referer", "http://www.invalid-referer.org")
			case tt.refererHTTPDowngrade:
				r.Header.Set("Referer", "http://www.gorillatoolkit.org/foobar")
			case tt.refererRelative:
				r.Header.Set("Referer", "/foobar")
			}

			// Set the CSRF token & associated cookie
			switch {
			case tt.tokenInvalid:
				setCookie(rr, r)
				r.Header.Set("X-CSRF-Token", "this-is-an-invalid-token")
			case tt.tokenValid:
				setCookie(rr, r)
				r.Header.Set("X-CSRF-Token", token)
			}

			rr = httptest.NewRecorder()
			p.ServeHTTP(rr, r)

			if tt.want && rr.Code != http.StatusOK {
				t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
					rr.Code, http.StatusOK)
			}

			if tt.want && !flag {
				t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
					flag, true)

			}
			if !tt.want && flag {
				t.Fatalf("middleware failed to reject the request: got %v want %v", flag, false)
			}
		})
	}
}

func createRequest(method, path string, useTLS bool) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Host = "www.gorillatoolkit.org"
	if !useTLS {
		return PlaintextHTTPRequest(r)
	}
	return r
}

// TestFailureResponseCacheHeaders is the fixed matrix of status codes and
// cache headers that every CSRF rejection must satisfy:
//   - HTTP 403 Forbidden
//   - Vary: Cookie (the same identity cache boundary as a success response)
//   - Cache-Control: no-store and Pragma: no-cache (never cached)
//   - no Set-Cookie (a rejection never carries a reusable token)
func TestFailureResponseCacheHeaders(t *testing.T) {
	s := http.NewServeMux()

	var token string
	s.Handle("/", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		token = Token(r)
	}))

	p := Protect(testKey)(s)

	// Obtain a valid CSRF cookie + masked token via a GET request.
	getRR := httptest.NewRecorder()
	p.ServeHTTP(getRR, createRequest("GET", "/", true))
	validCookie := getRR.Header().Get("Set-Cookie")

	tests := []struct {
		name    string
		useTLS  bool
		prepare func(r *http.Request)
	}{
		{
			name:   "POST without cookie",
			useTLS: false,
			prepare: func(r *http.Request) {
				r.Header.Set("Origin", "http://www.gorillatoolkit.org")
			},
		},
		{
			name:   "POST with malformed cookie",
			useTLS: true,
			prepare: func(r *http.Request) {
				r.Header.Set("Origin", "https://www.gorillatoolkit.org")
				r.Header.Set("Cookie", cookieName+"=tampered-value")
				r.Header.Set("X-CSRF-Token", token)
			},
		},
		{
			name:   "POST missing request token",
			useTLS: true,
			prepare: func(r *http.Request) {
				r.Header.Set("Cookie", validCookie)
				r.Header.Set("Referer", "https://www.gorillatoolkit.org/")
			},
		},
		{
			name:   "POST with mismatched token",
			useTLS: true,
			prepare: func(r *http.Request) {
				r.Header.Set("Cookie", validCookie)
				r.Header.Set("X-CSRF-Token", "not-the-issued-token")
				r.Header.Set("Referer", "https://www.gorillatoolkit.org/")
			},
		},
		{
			name:   "POST with untrusted origin",
			useTLS: true,
			prepare: func(r *http.Request) {
				r.Header.Set("Cookie", validCookie)
				r.Header.Set("Origin", "https://evil.example.org")
			},
		},
		{
			name:   "POST without referer over TLS",
			useTLS: true,
			prepare: func(r *http.Request) {
				r.Header.Set("Cookie", validCookie)
			},
		},
		{
			name:   "POST with cross-site referer",
			useTLS: true,
			prepare: func(r *http.Request) {
				r.Header.Set("Cookie", validCookie)
				r.Header.Set("Referer", "https://evil.example.org/")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := createRequest("POST", "/", tt.useTLS)
			tt.prepare(r)

			rr := httptest.NewRecorder()
			p.ServeHTTP(rr, r)

			if rr.Code != http.StatusForbidden {
				t.Fatalf("status: got %v want %v", rr.Code, http.StatusForbidden)
			}

			if got := rr.Header().Get("Vary"); got != "Cookie" {
				t.Fatalf("Vary: got %q want %q", got, "Cookie")
			}

			if got := rr.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control: got %q want %q", got, "no-store")
			}

			if got := rr.Header().Get("Pragma"); got != "no-cache" {
				t.Fatalf("Pragma: got %q want %q", got, "no-cache")
			}

			if got := rr.Header().Get("Set-Cookie"); got != "" {
				t.Fatalf("rejection must not carry a reusable token cookie: got %q", got)
			}
		})
	}
}

// TestSuccessResponseCacheBoundary pins the success side of the matrix: a
// successful response is still allowed to establish the session cookie, but it
// must carry the same Vary: Cookie identity boundary and must not be marked
// no-store by the middleware.
func TestSuccessResponseCacheBoundary(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey)(s)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, createRequest("GET", "/", true))

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %v want %v", rr.Code, http.StatusOK)
	}

	if got := rr.Header().Get("Vary"); got != "Cookie" {
		t.Fatalf("Vary: got %q want %q", got, "Cookie")
	}

	if rr.Header().Get("Set-Cookie") == "" {
		t.Fatal("success response must still issue the session cookie")
	}

	if got := rr.Header().Get("Cache-Control"); got == "no-store" {
		t.Fatalf("middleware must not mark successful responses no-store: got %q", got)
	}
}

// TestRejectionHeadersWithCustomErrorHandler ensures the cache boundary is
// applied before the configurable ErrorHandler runs, so custom handlers cannot
// accidentally emit a cacheable, cookieless rejection.
func TestRejectionHeadersWithCustomErrorHandler(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)

	errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if FailureReason(r) == nil {
			t.Error("failure reason not propagated to custom error handler")
		}
		w.WriteHeader(http.StatusForbidden)
	})

	p := Protect(testKey, ErrorHandler(errorHandler))(s)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, createRequest("POST", "/", false))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status: got %v want %v", rr.Code, http.StatusForbidden)
	}

	if got := rr.Header().Get("Vary"); got != "Cookie" {
		t.Fatalf("Vary: got %q want %q", got, "Cookie")
	}

	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control: got %q want %q", got, "no-store")
	}

	if got := rr.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma: got %q want %q", got, "no-cache")
	}

	if got := rr.Header().Get("Set-Cookie"); got != "" {
		t.Fatalf("rejection must not carry a reusable token cookie: got %q", got)
	}
}
