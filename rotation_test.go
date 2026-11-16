package csrf

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
)

// newRotationServer builds a middleware-wrapped mux that exposes the current
// masked CSRF token on GET and accepts authenticated POSTs. The returned
// protector is used directly (via ServeHTTP) so each test can drive its own
// request/response cycle.
func newRotationServer(t *testing.T, opts ...Option) http.Handler {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-CSRF-Token", Token(r))
		w.WriteHeader(http.StatusOK)
	})

	return Protect(testKey, opts...)(mux)
}

func issueToken(t *testing.T, p http.Handler) (cookie, masked string) {
	t.Helper()

	r := createRequest("GET", "/", false)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET to issue a token failed: got %v want %v", rr.Code, http.StatusOK)
	}

	return setCookieValue(rr), rr.Header().Get("X-CSRF-Token")
}

func setCookieValue(rr *httptest.ResponseRecorder) string {
	// The recorder stores the full Set-Cookie attribute line; only the
	// name=value pair is valid as a Cookie request header.
	full := rr.Header().Get("Set-Cookie")
	if idx := strings.IndexByte(full, ';'); idx >= 0 {
		return full[:idx]
	}

	return full
}

func postWithToken(p http.Handler, cookie, masked string) *httptest.ResponseRecorder {
	r := createRequest("POST", "/", false)
	r.Header.Set("Cookie", cookie)
	r.Header.Set("X-CSRF-Token", masked)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, r)

	return rr
}

// newTestCookieStore builds a cookieStore identical to the one Protect creates
// by default, for use by the blocking test store.
func newTestCookieStore(_ http.Handler) *cookieStore {
	sc := securecookie.New(testKey, nil)
	sc.SetSerializer(securecookie.JSONEncoder{})
	sc.MaxAge(defaultAge)

	return &cookieStore{
		name:     cookieName,
		maxAge:   defaultAge,
		secure:   true,
		httpOnly: true,
		sameSite: SameSiteLaxMode,
		sc:       sc,
	}
}

func createRequestWithCookie(cookie string) *http.Request {
	r := createRequest("GET", "/", false)
	r.Header.Set("Cookie", cookie)
	return r
}

// blockingStore wraps the standard cookieStore and parks the first rotation
// Save (the leader) until proceed is closed. Followers register on the
// replayGuard's inflight barrier while the leader is parked, giving tests a
// deterministic concurrent-submission window without sleeps.
type blockingStore struct {
	*cookieStore
	leaderSave chan struct{}
	proceed    chan struct{}
	guard      *replayGuard
	token      []byte
	wantFollow int
	armed      bool
	mu         sync.Mutex
}

func (b *blockingStore) Save(token []byte, w http.ResponseWriter) error {
	b.mu.Lock()
	if b.armed {
		b.armed = false
	} else {
		b.mu.Unlock()
		return b.cookieStore.Save(token, w)
	}
	b.mu.Unlock()

	{
		close(b.leaderSave)
		// Park until every duplicate request has joined the inflight barrier.
		deadline := time.Now().Add(5 * time.Second)
		for {
			b.guard.mu.Lock()
			got := 0
			if call, ok := b.guard.inflight[string(b.token)]; ok {
				got = call.followers
			}
			b.guard.mu.Unlock()

			if got >= b.wantFollow || time.Now().After(deadline) {
				break
			}

			time.Sleep(time.Millisecond)
		}
		<-b.proceed
	}

	return b.cookieStore.Save(token, w)
}

// TestTokenRotationRejectsReplay verifies the one-time-use semantics: a token
// that has already been presented on a successful unsafe request is rejected
// when replayed, while the rotated token issued in the response remains valid.
func TestTokenRotationRejectsReplay(t *testing.T) {
	p := newRotationServer(t)

	cookie, masked := issueToken(t, p)

	// First submission succeeds and rotates the session token.
	first := postWithToken(p, cookie, masked)
	if first.Code != http.StatusOK {
		t.Fatalf("first authenticated POST failed: got %v want %v", first.Code, http.StatusOK)
	}

	rotatedCookie := setCookieValue(first)
	rotatedMasked := first.Header().Get("X-CSRF-Token")
	if rotatedCookie == "" || rotatedCookie == cookie {
		t.Fatalf("response did not rotate the session cookie: got %q", rotatedCookie)
	}
	if rotatedMasked == "" || rotatedMasked == masked {
		t.Fatalf("response did not rotate the masked token: got %q", rotatedMasked)
	}

	// Replaying the consumed token with the original session state is rejected.
	replay := postWithToken(p, cookie, masked)
	if replay.Code != http.StatusForbidden {
		t.Fatalf("replay of a consumed token was not rejected: got %v want %v",
			replay.Code, http.StatusForbidden)
	}

	// The rotated token works on the next request.
	second := postWithToken(p, rotatedCookie, rotatedMasked)
	if second.Code != http.StatusOK {
		t.Fatalf("POST with the rotated token failed: got %v want %v",
			second.Code, http.StatusOK)
	}

	// A leaked masked token cannot be replayed even against the rotated cookie.
	stolen := postWithToken(p, rotatedCookie, masked)
	if stolen.Code != http.StatusForbidden {
		t.Fatalf("leaked old token accepted after rotation: got %v want %v",
			stolen.Code, http.StatusForbidden)
	}
}

// TestReplayFailureReason verifies that replay rejections surface the same
// ErrBadToken failure reason as any other malformed/non-matching token.
func TestReplayFailureReason(t *testing.T) {
	var failure error

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(_ http.ResponseWriter, r *http.Request) {
		failure = FailureReason(r)
	})

	p := Protect(testKey, ErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failure = FailureReason(r)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	})))(mux)

	// Obtain the masked token directly from the request context.
	var masked string
	tokenMux := http.NewServeMux()
	tokenMux.HandleFunc("/", func(_ http.ResponseWriter, r *http.Request) {
		masked = Token(r)
	})

	tokenP := Protect(testKey)(tokenMux)
	issueRR := httptest.NewRecorder()
	tokenP.ServeHTTP(issueRR, createRequest("GET", "/", false))
	cookie := setCookieValue(issueRR)

	if rr := postWithToken(p, cookie, masked); rr.Code != http.StatusOK {
		t.Fatalf("first authenticated POST failed: got %v", rr.Code)
	}

	if rr := postWithToken(p, cookie, masked); rr.Code != http.StatusForbidden {
		t.Fatalf("replay was not rejected: got %v want %v", rr.Code, http.StatusForbidden)
	}

	if failure != ErrBadToken {
		t.Fatalf("replay returned unexpected failure reason: got %v want %v", failure, ErrBadToken)
	}
}

// TestConcurrentDuplicateSubmissions verifies that parallel submissions of the
// same token (double clicks, retries racing the response) are not mutually
// killed: at least one succeeds and no request is reported as a replay.
func TestConcurrentDuplicateSubmissions(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-CSRF-Token", Token(r))
		w.WriteHeader(http.StatusOK)
	})

	const n = 8

	// The blocking store parks the leader's rotation Save until all duplicate
	// requests have registered on the guard's inflight barrier, making the
	// fan-out deterministic without timing assumptions.
	blocking := &blockingStore{
		cookieStore: newTestCookieStore(mux),
		leaderSave:  make(chan struct{}),
		proceed:     make(chan struct{}),
		wantFollow:  n - 1,
	}

	cs := parseOptions(mux)
	cs.opts.ErrorHandler = http.HandlerFunc(unauthorizedHandler)
	cs.opts.CookieName = cookieName
	cs.opts.FieldName = fieldName
	cs.opts.RequestHeader = headerName
	cs.sc = securecookie.New(testKey, nil)
	cs.sc.SetSerializer(securecookie.JSONEncoder{})
	cs.sc.MaxAge(cs.opts.MaxAge)
	cs.st = blocking
	cs.rg = newReplayGuard(time.Minute)
	blocking.guard = cs.rg

	p := cs

	issueRR := httptest.NewRecorder()
	p.ServeHTTP(issueRR, createRequest("GET", "/", false))
	cookie := setCookieValue(issueRR)
	masked := issueRR.Header().Get("X-CSRF-Token")

	// Capture the real token the guard will key on for these submissions.
	realToken, err := blocking.cookieStore.Get(createRequestWithCookie(cookie))
	if err != nil {
		t.Fatalf("failed to read issued real token: %v", err)
	}
	blocking.token = realToken
	blocking.armed = true

	var wg sync.WaitGroup
	results := make(chan int, n)

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			results <- postWithToken(p, cookie, masked).Code
		}()
	}

	<-blocking.leaderSave
	close(blocking.proceed)
	wg.Wait()
	close(results)

	successes := 0
	for code := range results {
		if code == http.StatusOK {
			successes++
			continue
		}

		t.Fatalf("concurrent duplicate submission rejected: got %v want %v",
			code, http.StatusOK)
	}

	if successes == 0 {
		t.Fatalf("no concurrent submission succeeded: got 0 want at least 1")
	}
}

// TestLegacyCookieCompatible verifies that a session cookie produced by the
// pre-rotation implementation (a securecookie-encoded 32-byte real token) is
// still accepted and that the first successful unsafe request rotates it.
func TestLegacyCookieCompatible(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-CSRF-Token", Token(r))
	})

	p := Protect(testKey)(mux)

	// Bootstrap a legacy-format cookie through a normal GET: the cookieStore
	// payload is still just the 32-byte real token, exactly as before.
	cookie, masked := issueToken(t, p)

	// Decode the legacy cookie and confirm it holds a single 32-byte token in
	// the historical format.
	sc := securecookie.New(testKey, nil)
	sc.SetSerializer(securecookie.JSONEncoder{})
	var legacyToken []byte
	if err := sc.Decode(cookieName, strings.TrimPrefix(cookie, cookieName+"="), &legacyToken); err != nil {
		t.Fatalf("failed to decode legacy cookie: %v", err)
	}

	if len(legacyToken) != tokenLength {
		t.Fatalf("legacy cookie payload has unexpected length: got %d want %d",
			len(legacyToken), tokenLength)
	}

	rr := postWithToken(p, cookie, masked)
	if rr.Code != http.StatusOK {
		t.Fatalf("legacy cookie token rejected: got %v want %v", rr.Code, http.StatusOK)
	}

	if setCookieValue(rr) == cookie {
		t.Fatalf("legacy session token was not rotated after use")
	}
}

// TestCustomStoreRotation verifies that custom store implementations only
// needing the original Get/Save interface keep working through rotation.
func TestCustomStoreRotation(t *testing.T) {
	mem := &memoryStore{tokens: make(map[string][]byte)}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-CSRF-Token", Token(r))
	})

	p := Protect(testKey, setStore(mem))(mux)

	cookie, masked := issueToken(t, p)

	first := postWithToken(p, cookie, masked)
	if first.Code != http.StatusOK {
		t.Fatalf("first POST via custom store failed: got %v want %v",
			first.Code, http.StatusOK)
	}

	if mem.saves < 2 {
		t.Fatalf("custom store did not persist the rotated token: got %d saves", mem.saves)
	}

	if replay := postWithToken(p, cookie, masked); replay.Code != http.StatusForbidden {
		t.Fatalf("replay via custom store was not rejected: got %v want %v",
			replay.Code, http.StatusForbidden)
	}

	rotatedCookie := setCookieValue(first)
	rotatedMasked := first.Header().Get("X-CSRF-Token")
	if second := postWithToken(p, rotatedCookie, rotatedMasked); second.Code != http.StatusOK {
		t.Fatalf("rotated token rejected via custom store: got %v want %v",
			second.Code, http.StatusOK)
	}
}

// memoryStore is a minimal store implementing only the original Get/Save
// interface, mirroring how downstream users plug in server-side sessions.
type memoryStore struct {
	mu     sync.Mutex
	tokens map[string][]byte
	saves  int
}

func (m *memoryStore) Get(r *http.Request) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil, err
	}

	token, ok := m.tokens[cookie.Value]
	if !ok {
		return nil, http.ErrNoCookie
	}

	return token, nil
}

func (m *memoryStore) Save(token []byte, w http.ResponseWriter) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := base64.RawURLEncoding.EncodeToString(token)
	m.tokens[id] = append([]byte(nil), token...)
	m.saves++
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: id})

	return nil
}
