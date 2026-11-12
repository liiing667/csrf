package csrf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestParseTrustedOrigin(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		want  string
		ok    bool
	}{
		{name: "https host", entry: "https://example.com", want: "https://example.com", ok: true},
		{name: "http host", entry: "http://example.com", want: "http://example.com", ok: true},
		{name: "https explicit port", entry: "https://example.com:8443", want: "https://example.com:8443", ok: true},
		{name: "http explicit port", entry: "http://example.com:8080", want: "http://example.com:8080", ok: true},
		{name: "https default port stripped", entry: "https://example.com:443", want: "https://example.com", ok: true},
		{name: "http default port stripped", entry: "http://example.com:80", want: "http://example.com", ok: true},
		{name: "upper case scheme and host", entry: "HTTPS://EXAMPLE.COM", want: "https://example.com", ok: true},
		{name: "ipv6 loopback", entry: "http://[::1]:3000", want: "http://[::1]:3000", ok: true},
		{name: "ipv4 loopback", entry: "http://127.0.0.1:3000", want: "http://127.0.0.1:3000", ok: true},

		{name: "bare host rejected", entry: "example.com", ok: false},
		{name: "bare host with port rejected", entry: "example.com:443", ok: false},
		{name: "path rejected", entry: "https://example.com/", ok: false},
		{name: "deep path rejected", entry: "https://example.com/foo", ok: false},
		{name: "query rejected", entry: "https://example.com?x=1", ok: false},
		{name: "fragment rejected", entry: "https://example.com#frag", ok: false},
		{name: "userinfo rejected", entry: "https://user:pass@example.com", ok: false},
		{name: "wildcard host rejected", entry: "https://*.example.com", ok: false},
		{name: "wildcard only rejected", entry: "*", ok: false},
		{name: "unsupported scheme rejected", entry: "ftp://example.com", ok: false},
		{name: "scheme only rejected", entry: "https://", ok: false},
		{name: "empty rejected", entry: "", ok: false},
		{name: "port zero rejected", entry: "https://example.com:0", ok: false},
		{name: "port overflow rejected", entry: "https://example.com:65536", ok: false},
		{name: "port non numeric rejected", entry: "https://example.com:https", ok: false},
		{name: "null origin rejected", entry: "null", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseTrustedOrigin(tt.entry)
			if ok != tt.ok {
				t.Fatalf("parseTrustedOrigin(%q) ok = %v, want %v (got key %q)", tt.entry, ok, tt.ok, got)
			}
			if ok && got != tt.want {
				t.Fatalf("parseTrustedOrigin(%q) = %q, want %q", tt.entry, got, tt.want)
			}
		})
	}
}

func TestOriginKey(t *testing.T) {
	tests := []struct {
		raw  string
		want string
		ok   bool
	}{
		{"https://example.com/path", "https://example.com", true},
		{"https://example.com:443/path", "https://example.com", true},
		{"http://example.com:80/path", "http://example.com", true},
		{"https://example.com:9999/path", "https://example.com:9999", true},
		{"HTTPS://Example.COM/Path", "https://example.com", true},
		{"http://[::1]:3000/foobar", "http://[::1]:3000", true},
		{"null", "", false},
		{"file:///etc/passwd", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			u, err := url.Parse(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			got, ok := originKey(u)
			if ok != tt.ok {
				t.Fatalf("originKey(%q) ok = %v, want %v", tt.raw, ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Fatalf("originKey(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestIsTrustedOrigin(t *testing.T) {
	cs := parseOptions(nil, TrustedOrigins([]string{
		"https://api.example.com",
		"http://localhost:3000",
		"https://cdn.example.com:8443",
		// Invalid entries are ignored rather than matching anything.
		"cdn.example.com",
		"https://*.example.com",
		"https://user@api.example.com",
	}))

	tests := []struct {
		raw  string
		want bool
	}{
		{"https://api.example.com", true},
		{"https://api.example.com:443", true},
		{"HTTPS://API.EXAMPLE.COM", true},
		{"http://api.example.com", false},
		{"https://api.example.com:8443", false},
		{"https://api.example.com/path", true},
		{"http://localhost:3000", true},
		{"https://localhost:3000", false},
		{"http://localhost", false},
		{"https://cdn.example.com:8443", true},
		{"https://cdn.example.com", false},
		{"https://evil.example.com", false},
		{"null", false},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			u, err := url.Parse(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got := isTrustedOrigin(cs.opts.trustedOrigins, u); got != tt.want {
				t.Fatalf("isTrustedOrigin(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

// TestTrustedOriginsMiddleware exercises both the Origin and Referer code
// paths through the full middleware to make sure scheme, host and port are
// matched identically in each.
func TestTrustedOriginsMiddleware(t *testing.T) {
	tests := []struct {
		name      string
		config    []string
		origin    string
		referer   string
		plaintext bool
		want      bool
	}{
		{
			name:   "origin full URL matches",
			config: []string{"https://api.example.com"},
			origin: "https://api.example.com",
			want:   true,
		},
		{
			name:   "origin scheme mismatch rejected",
			config: []string{"https://api.example.com"},
			origin: "http://api.example.com",
			want:   false,
		},
		{
			name:   "origin port mismatch rejected",
			config: []string{"https://api.example.com"},
			origin: "https://api.example.com:8443",
			want:   false,
		},
		{
			name:   "origin default port matches",
			config: []string{"https://api.example.com:443"},
			origin: "https://api.example.com",
			want:   true,
		},
		{
			name:   "origin userinfo rejected",
			config: []string{"https://api.example.com"},
			origin: "https://user:pass@api.example.com",
			want:   false,
		},
		{
			name:   "null origin rejected",
			config: []string{"https://api.example.com"},
			origin: "null",
			want:   false,
		},
		{
			name:    "referer full URL matches",
			config:  []string{"https://api.example.com"},
			referer: "https://api.example.com/foobar",
			want:    true,
		},
		{
			name:    "referer scheme mismatch rejected",
			config:  []string{"https://api.example.com"},
			referer: "http://api.example.com/foobar",
			want:    false,
		},
		{
			name:    "referer port mismatch rejected",
			config:  []string{"https://api.example.com"},
			referer: "https://api.example.com:8443/foobar",
			want:    false,
		},
		{
			name:    "bare host config never matches https",
			config:  []string{"api.example.com"},
			referer: "https://api.example.com/foobar",
			want:    false,
		},
		{
			name:      "cleartext origin matches explicit http entry",
			config:    []string{"http://api.example.com"},
			origin:    "http://api.example.com",
			plaintext: true,
			want:      true,
		},
		{
			name:      "cleartext origin not matched by https entry",
			config:    []string{"https://api.example.com"},
			origin:    "http://api.example.com",
			plaintext: true,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			p := Protect(testKey, TrustedOrigins(tt.config))(mux)

			var token string
			mux.HandleFunc("/", func(_ http.ResponseWriter, r *http.Request) {
				token = Token(r)
			})

			// Obtain a CSRF cookie via a GET request.
			getReq := createRequest("GET", "/", !tt.plaintext)
			getRR := httptest.NewRecorder()
			p.ServeHTTP(getRR, getReq)

			postReq := createRequest("POST", "/", !tt.plaintext)
			setCookie(getRR, postReq)
			postReq.Header.Set("X-CSRF-Token", token)
			if tt.origin != "" {
				postReq.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				postReq.Header.Set("Referer", tt.referer)
			}

			rr := httptest.NewRecorder()
			p.ServeHTTP(rr, postReq)

			if tt.want && rr.Code != 200 {
				t.Fatalf("expected request to pass: got status %d (reason: %v)", rr.Code, FailureReason(postReq))
			}
			if !tt.want && rr.Code != 403 {
				t.Fatalf("expected request to be rejected: got status %d", rr.Code)
			}
		})
	}
}
