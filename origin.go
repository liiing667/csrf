package csrf

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// defaultPorts maps a URL scheme to the port that is implied when no explicit
// port is supplied. Origins that only differ by the presence of the default
// port (e.g. https://example.com and https://example.com:443) represent the
// same origin and must compare equal.
var defaultPorts = map[string]string{
	"http":  "80",
	"https": "443",
}

// parseTrustedOrigin validates and normalizes a TrustedOrigins entry.
//
// Entries must be absolute origins of the form "scheme://host[:port]" using
// the http or https scheme. Entries containing userinfo, a path, a query, a
// fragment, a wildcard, or an invalid port are rejected. Scheme-less hosts
// (the format accepted by csrf versions up to v1.7.x) are also rejected:
// migrate them to an explicit origin such as "https://example.com", or list
// both "http://example.com" and "https://example.com" if cleartext traffic
// must remain trusted.
//
// The returned key is canonicalized to a lower-case scheme and host with the
// default port for the scheme stripped, so it can be compared against the
// canonical form of request Origin/Referer URLs.
func parseTrustedOrigin(entry string) (string, bool) {
	if entry == "" || strings.ContainsAny(entry, "*?#") {
		return "", false
	}

	u, err := url.Parse(entry)
	if err != nil {
		return "", false
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	if u.User != nil || u.Host == "" {
		return "", false
	}
	// Origins never carry a path, query, or fragment. Reject anything beyond
	// the scheme and authority components.
	if u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return "", false
	}

	host := u.Hostname()
	if host == "" {
		return "", false
	}
	// Reject userinfo that url.Parse may have tolerated inside Host.
	if strings.ContainsAny(host, "@/") {
		return "", false
	}

	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", false
		}
		if defaultPorts[u.Scheme] == strconv.Itoa(n) {
			port = ""
		}
	}

	return canonicalOrigin(u.Scheme, host, port), true
}

// canonicalOrigin builds the normalized origin key used for comparisons. The
// scheme and host are lower-cased, an IPv6 host is bracketed, and the port is
// omitted when it is empty (callers strip scheme-default ports beforehand).
func canonicalOrigin(scheme, host, port string) string {
	scheme = strings.ToLower(scheme)
	host = strings.ToLower(host)
	if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port == "" {
		return scheme + "://" + host
	}
	return scheme + "://" + host + ":" + port
}

// originKey returns the canonical origin key of a parsed request URL, or
// false when the URL does not describe a valid http/https origin.
func originKey(u *url.URL) (string, bool) {
	if u == nil {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}

	host := u.Hostname()
	if host == "" || u.User != nil {
		return "", false
	}

	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil {
			return "", false
		}
		if defaultPorts[u.Scheme] == strconv.Itoa(n) {
			port = ""
		}
	}

	return canonicalOrigin(u.Scheme, host, port), true
}

// isTrustedOrigin reports whether the given parsed request URL matches one of
// the configured trusted origins. Both the Origin and Referer code paths use
// this helper so the same normalization and matching rules apply to each.
func isTrustedOrigin(trusted map[string]struct{}, u *url.URL) bool {
	key, ok := originKey(u)
	if !ok {
		return false
	}
	_, ok = trusted[key]
	return ok
}
