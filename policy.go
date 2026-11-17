package csrf

import (
	"errors"
	"net/http"
	"strings"
)

var (
	// ErrInvalidSameSite is returned at startup when the configured SameSite
	// mode is not one of the SameSiteMode constants exported by this package.
	ErrInvalidSameSite = errors.New("invalid SameSite mode")
	// ErrSameSiteNoneRequiresSecure is returned at startup when the cookie is
	// configured with SameSite=None without the Secure attribute. Browsers
	// reject such cookies, so the issued token could never be sent back.
	ErrSameSiteNoneRequiresSecure = errors.New("SameSite=None requires the Secure attribute")
	// ErrInvalidDomain is returned at startup when the configured cookie
	// domain is not a bare hostname (e.g. it contains a scheme, path or other
	// characters that are illegal in a cookie attribute), which would cause
	// the cookie to be scoped to the wrong domain or be rejected outright.
	ErrInvalidDomain = errors.New("invalid cookie domain")
	// ErrInvalidPath is returned at startup when the configured cookie path
	// does not start with "/". Browsers ignore such Path attributes, meaning
	// the issued cookie would not be returned on subsequent requests.
	ErrInvalidPath = errors.New("invalid cookie path")
	// ErrPolicyConflict is returned at startup when the policy resolved from
	// the functional options does not match the policy baked into a custom
	// store. A single CookiePolicy must govern both token issuance and
	// validation to avoid cookies that can be issued but never returned.
	ErrPolicyConflict = errors.New("cookie policy conflict between options and store")
)

// PolicyError describes a cookie policy problem detected while building the
// CSRF middleware. It always wraps one of the package-level policy errors and,
// where relevant, names the conflicting policy field.
type PolicyError struct {
	// Field is the CookiePolicy field that caused the failure, or empty when
	// the failure is not tied to a single field.
	Field string
	// Err is the wrapped sentinel error (e.g. ErrInvalidDomain).
	Err error
}

func (e *PolicyError) Error() string {
	if e.Field == "" {
		return errorPrefix + e.Err.Error()
	}
	return errorPrefix + e.Field + ": " + e.Err.Error()
}

func (e *PolicyError) Unwrap() error {
	return e.Err
}

// CookiePolicy is an immutable snapshot of the cookie attributes used by the
// CSRF middleware. One resolved snapshot is shared by the functional options,
// the token store and the middleware so that the cookie written when a token
// is issued is identical to the cookie inspected when a token is validated.
//
// The resolved snapshot can be audited at runtime via Policy(r).
type CookiePolicy struct {
	// Name is the cookie name.
	Name string
	// MaxAge is the cookie MaxAge in seconds.
	MaxAge int
	// Domain is the cookie Domain attribute. Empty means the request host.
	Domain string
	// Path is the cookie Path attribute.
	Path string
	// HttpOnly controls the cookie HttpOnly attribute.
	HttpOnly bool
	// Secure controls the cookie Secure attribute.
	Secure bool
	// SameSite controls the cookie SameSite attribute.
	SameSite SameSiteMode
}

// validate checks the snapshot for combinations that browsers would reject or
// that would route the cookie incorrectly. It is called once while building
// the middleware so that conflicting configuration fails at startup.
func (p CookiePolicy) validate() error {
	switch p.SameSite {
	case SameSiteDefaultMode, SameSiteLaxMode, SameSiteStrictMode, SameSiteNoneMode:
	default:
		return &PolicyError{Field: "SameSite", Err: ErrInvalidSameSite}
	}

	if p.SameSite == SameSiteNoneMode && !p.Secure {
		return &PolicyError{Field: "SameSite", Err: ErrSameSiteNoneRequiresSecure}
	}

	if p.Domain != "" {
		if strings.ContainsAny(p.Domain, " \t\r\n;,\\/") || strings.Contains(p.Domain, "=") {
			return &PolicyError{Field: "Domain", Err: ErrInvalidDomain}
		}
	}

	if p.Path != "" && !strings.HasPrefix(p.Path, "/") {
		return &PolicyError{Field: "Path", Err: ErrInvalidPath}
	}

	return nil
}

// conflictsWith reports whether another snapshot (typically provided by a
// custom store) differs on the browser-controlled routing attributes. A
// mismatch means the store could issue a cookie the middleware cannot read
// back, so middleware construction must fail.
func (p CookiePolicy) conflictsWith(other CookiePolicy) (string, bool) {
	switch {
	case p.SameSite != other.SameSite:
		return "SameSite", true
	case p.Secure != other.Secure:
		return "Secure", true
	case p.Path != other.Path:
		return "Path", true
	case p.Domain != other.Domain:
		return "Domain", true
	default:
		return "", false
	}
}

// PolicyCarrier is implemented by stores that carry their own cookie policy.
// When a custom store implements PolicyCarrier, its CookiePolicy is compared
// with the policy resolved from the functional options at startup. Any
// mismatch on SameSite, Secure, Path or Domain aborts middleware construction.
type PolicyCarrier interface {
	CookiePolicy() CookiePolicy
}

// Policy returns the immutable CookiePolicy snapshot governing the request, or
// the zero value if the CSRF middleware has not run. It allows applications to
// audit the exact SameSite, Secure, Path and Domain attributes used for both
// token issuance and validation.
func Policy(r *http.Request) CookiePolicy {
	if val, err := contextGet(r, policyKey); err == nil {
		if policy, ok := val.(CookiePolicy); ok {
			return policy
		}
	}

	return CookiePolicy{}
}
