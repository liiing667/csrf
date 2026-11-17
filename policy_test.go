package csrf

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// policyStore is a configurable store that advertises its own CookiePolicy,
// exercising the store-vs-options conflict checks.
type policyStore struct {
	policy CookiePolicy
	token  []byte
}

func (s *policyStore) CookiePolicy() CookiePolicy {
	return s.policy
}

func (s *policyStore) Get(*http.Request) ([]byte, error) {
	if len(s.token) == 0 {
		return nil, http.ErrNoCookie
	}
	return s.token, nil
}

func (s *policyStore) Save(token []byte, _ http.ResponseWriter) error {
	s.token = append([]byte(nil), token...)
	return nil
}

// silentPolicyStore carries a policy but fails the save step, mirroring the
// existing brokenSaveStore test fixture.
type silentPolicyStore struct {
	policy CookiePolicy
}

func (s *silentPolicyStore) CookiePolicy() CookiePolicy {
	return s.policy
}

func (s *silentPolicyStore) Get(*http.Request) ([]byte, error) {
	return generateRandomBytes(24)
}

func (s *silentPolicyStore) Save([]byte, http.ResponseWriter) error {
	return errors.New("test error")
}

func defaultPolicy() CookiePolicy {
	return CookiePolicy{
		Name:     cookieName,
		MaxAge:   defaultAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: SameSiteLaxMode,
	}
}

// TestDefaultPolicySnapshot checks that the historical defaults remain intact
// and are exposed both via the store and the request context.
func TestDefaultPolicySnapshot(t *testing.T) {
	s := http.NewServeMux()
	var seen CookiePolicy
	s.HandleFunc("/audit", func(_ http.ResponseWriter, r *http.Request) {
		seen = Policy(r)
	})

	p := Protect(testKey)(s)

	handler := p.(*csrf)
	store := handler.st.(*cookieStore)

	if got, want := store.CookiePolicy(), defaultPolicy(); got != want {
		t.Fatalf("store policy does not match resolved defaults: got %+v want %+v", got, want)
	}

	if handler.policy != store.policy {
		t.Fatalf("middleware and store do not share one policy snapshot: %+v vs %+v",
			handler.policy, store.policy)
	}

	r := createRequest("GET", "/audit", false)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("middleware failed to pass to the next handler: got %v want %v",
			rr.Code, http.StatusOK)
	}

	if seen != defaultPolicy() {
		t.Fatalf("Policy(r) did not return the default snapshot: got %+v want %+v",
			seen, defaultPolicy())
	}

	cookie := rr.Header().Get("Set-Cookie")
	for _, want := range []string{"SameSite=Lax", "Secure", "HttpOnly", cookieName + "="} {
		if !strings.Contains(cookie, want) {
			t.Fatalf("default cookie missing %q: got %s", want, cookie)
		}
	}
}

// TestPolicyWithoutMiddleware ensures Policy returns the zero value rather
// than panicking when the middleware has not run.
func TestPolicyWithoutMiddleware(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if Policy(r) != (CookiePolicy{}) {
		t.Fatalf("Policy returned a non-zero snapshot without middleware: %+v", Policy(r))
	}
}

// TestPolicyOptionsFlowToSnapshot checks that every functional option lands in
// the single snapshot used by both the middleware and the store.
func TestPolicyOptionsFlowToSnapshot(t *testing.T) {
	opts := []Option{
		CookieName("tenant_csrf"),
		MaxAge(600),
		Domain("example.com"),
		Path("/tenant/"),
		HttpOnly(false),
		Secure(false),
		SameSite(SameSiteStrictMode),
	}

	handler := Protect(testKey, opts...)(nil).(*csrf)
	store := handler.st.(*cookieStore)

	want := CookiePolicy{
		Name:     "tenant_csrf",
		MaxAge:   600,
		Domain:   "example.com",
		Path:     "/tenant/",
		HttpOnly: false,
		Secure:   false,
		SameSite: SameSiteStrictMode,
	}

	if handler.policy != want {
		t.Fatalf("middleware snapshot not built from options: got %+v want %+v",
			handler.policy, want)
	}
	if store.CookiePolicy() != want {
		t.Fatalf("store snapshot not built from options: got %+v want %+v",
			store.CookiePolicy(), want)
	}
}

// TestPolicyAvailableInErrorHandler verifies that error responses can audit
// the exact policy in force even when validation fails.
func TestPolicyAvailableInErrorHandler(t *testing.T) {
	var seen CookiePolicy
	errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = Policy(r)
		w.WriteHeader(http.StatusForbidden)
	})

	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey, ErrorHandler(errorHandler))(s)

	r := createRequest("POST", "/", true)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 from error handler: got %v", rr.Code)
	}
	if seen != defaultPolicy() {
		t.Fatalf("error handler could not audit the policy: got %+v want %+v",
			seen, defaultPolicy())
	}
}

// TestStartupValidationFailures covers every static conflict that must abort
// middleware construction instead of producing an unusable cookie.
func TestStartupValidationFailures(t *testing.T) {
	tests := []struct {
		name    string
		opts    []Option
		wantErr error
		field   string
	}{
		{
			name:    "SameSite None without Secure is rejected",
			opts:    []Option{SameSite(SameSiteNoneMode), Secure(false)},
			wantErr: ErrSameSiteNoneRequiresSecure,
			field:   "SameSite",
		},
		{
			name:    "unknown SameSite mode is rejected",
			opts:    []Option{SameSite(SameSiteMode(99))},
			wantErr: ErrInvalidSameSite,
			field:   "SameSite",
		},
		{
			name:    "domain with a scheme is rejected",
			opts:    []Option{Domain("https://example.com")},
			wantErr: ErrInvalidDomain,
			field:   "Domain",
		},
		{
			name:    "domain with a path is rejected",
			opts:    []Option{Domain("example.com/tenant")},
			wantErr: ErrInvalidDomain,
			field:   "Domain",
		},
		{
			name:    "relative path is rejected",
			opts:    []Option{Path("relative/path")},
			wantErr: ErrInvalidPath,
			field:   "Path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var recovered any
			func() {
				defer func() {
					recovered = recover()
				}()
				Protect(testKey, tt.opts...)(nil)
			}()

			if recovered == nil {
				t.Fatal("expected startup panic, got none")
			}

			policyErr, ok := recovered.(*PolicyError)
			if !ok {
				t.Fatalf("expected *PolicyError, got %T: %v", recovered, recovered)
			}
			if !errors.Is(policyErr, tt.wantErr) {
				t.Fatalf("wrapped error mismatch: got %v want %v", policyErr.Err, tt.wantErr)
			}
			if policyErr.Field != tt.field {
				t.Fatalf("field mismatch: got %q want %q", policyErr.Field, tt.field)
			}
		})
	}
}

// TestSameSiteNoneWithSecureStarts confirms the valid counterpart of the
// SameSite=None rejection still works, preserving the documented ability to
// opt into cross-site cookies.
func TestSameSiteNoneWithSecureStarts(t *testing.T) {
	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	handler := Protect(testKey, SameSite(SameSiteNoneMode), Secure(true))(s)
	cs := handler.(*csrf)

	if cs.policy.SameSite != SameSiteNoneMode || !cs.policy.Secure {
		t.Fatalf("valid SameSite=None + Secure policy was rejected: %+v", cs.policy)
	}

	r := createRequest("GET", "/", true)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, r)

	cookie := rr.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "SameSite=None") || !strings.Contains(cookie, "Secure") {
		t.Fatalf("cookie does not carry SameSite=None; Secure: got %s", cookie)
	}
}

// TestStorePolicyConflict aborts startup when a custom store would issue a
// cookie with different routing attributes than the middleware expects back.
func TestStorePolicyConflict(t *testing.T) {
	tests := []struct {
		name  string
		store CookiePolicy
		field string
	}{
		{"SameSite mismatch", CookiePolicy{SameSite: SameSiteStrictMode, Secure: true}, "SameSite"},
		{"Secure mismatch", CookiePolicy{SameSite: SameSiteLaxMode, Secure: false}, "Secure"},
		{"Path mismatch", CookiePolicy{SameSite: SameSiteLaxMode, Secure: true, Path: "/other"}, "Path"},
		{"Domain mismatch", CookiePolicy{SameSite: SameSiteLaxMode, Secure: true, Domain: "wrong.example"}, "Domain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var recovered any
			func() {
				defer func() {
					recovered = recover()
				}()
				Protect(testKey, setStore(&policyStore{policy: tt.store}))(nil)
			}()

			policyErr, ok := recovered.(*PolicyError)
			if !ok {
				t.Fatalf("expected *PolicyError, got %T: %v", recovered, recovered)
			}
			if !errors.Is(policyErr, ErrPolicyConflict) {
				t.Fatalf("expected ErrPolicyConflict, got %v", policyErr.Err)
			}
			if policyErr.Field != tt.field {
				t.Fatalf("conflict field mismatch: got %q want %q", policyErr.Field, tt.field)
			}
		})
	}
}

// TestMatchingStorePolicyStarts ensures a custom store whose policy matches the
// resolved snapshot is accepted and still serves requests.
func TestMatchingStorePolicyStarts(t *testing.T) {
	store := &policyStore{policy: defaultPolicy()}

	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey, setStore(store))(s)

	r := createRequest("GET", "/", false)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("matching custom store was rejected at runtime: got %v", rr.Code)
	}
	if len(store.token) != tokenLength {
		t.Fatalf("token was not saved via the custom store: got %d bytes", len(store.token))
	}
}

// TestPolicySnapshotRoundTrip drives a full issue -> submit cycle and checks
// the cookie written by the store carries the audited snapshot attributes.
func TestPolicySnapshotRoundTrip(t *testing.T) {
	opts := []Option{
		CookieName("tenant_csrf"),
		Domain("example.com"),
		Path("/tenant/"),
		SameSite(SameSiteNoneMode),
		Secure(true),
	}

	s := http.NewServeMux()
	var token string
	s.HandleFunc("/", func(_ http.ResponseWriter, r *http.Request) {
		token = Token(r)
		if Policy(r).Domain != "example.com" {
			t.Fatalf("audited policy does not reflect options: %+v", Policy(r))
		}
	})

	p := Protect(testKey, opts...)(s)

	r := createRequest("GET", "/", true)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	cookie := rr.Header().Get("Set-Cookie")
	for _, want := range []string{
		"tenant_csrf=",
		"Domain=example.com",
		"Path=/tenant/",
		"SameSite=None",
		"Secure",
	} {
		if !strings.Contains(cookie, want) {
			t.Fatalf("issued cookie missing %q: got %s", want, cookie)
		}
	}

	// The same store must accept the cookie it issued on validation.
	r = createRequest("POST", "/", true)
	setCookie(rr, r)
	r.Header.Set("X-CSRF-Token", token)
	r.Header.Set("Origin", "https://www.gorillatoolkit.org")

	rr = httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("cookie issued from the snapshot was not accepted on validation: got %v", rr.Code)
	}
}

// TestPolicyCarrierOnFailingStore keeps the broken-store behavior while proving
// a matching advertised policy does not mask unrelated save errors.
func TestPolicyCarrierOnFailingStore(t *testing.T) {
	store := &silentPolicyStore{policy: defaultPolicy()}

	s := http.NewServeMux()
	s.HandleFunc("/", testHandler)
	p := Protect(testKey, setStore(store))(s)

	r := createRequest("GET", "/", false)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("broken store did not set an error status: got %v want %v",
			rr.Code, http.StatusForbidden)
	}
}
