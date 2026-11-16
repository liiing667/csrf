package csrf

import (
	"sort"
	"sync"
	"time"
)

// replayGuardMaxEntries bounds the number of consumed tokens retained by a
// single replayGuard. Once the bound is reached, expired entries are pruned
// and, if necessary, the oldest entries are evicted.
const replayGuardMaxEntries = 1024

// inflightCall represents the in-flight consumption of a real token.
// Concurrent requests presenting the same token wait on done instead of being
// rejected as replays.
type inflightCall struct {
	done chan struct{}
	// err holds any rotation error encountered by the leader so that waiting
	// followers fail with the same reason.
	err error
	// newToken is the rotated real token shared with waiting followers so
	// their response context exposes the same token the leader persisted.
	newToken []byte
	// followers counts duplicate requests registered on this barrier.
	followers int
}

type consumedToken struct {
	expiresAt time.Time
}

// replayGuard enforces one-time use of real CSRF tokens while allowing
// concurrent (duplicate) submissions of the same token to succeed. It is an
// in-process, best-effort cache: the session cookie remains the source of
// truth for the token itself, so the existing stateless mask design and store
// implementations keep working unchanged.
type replayGuard struct {
	mu       sync.Mutex
	inflight map[string]*inflightCall
	consumed map[string]consumedToken
	ttl      time.Duration
	now      func() time.Time
}

func newReplayGuard(ttl time.Duration) *replayGuard {
	if ttl <= 0 {
		ttl = time.Duration(defaultAge) * time.Second
	}

	return &replayGuard{
		inflight: make(map[string]*inflightCall),
		consumed: make(map[string]consumedToken),
		ttl:      ttl,
		now:      time.Now,
	}
}

// begin registers an attempt to consume the supplied real token.
//
// If the token has already been consumed and its entry has not expired,
// replay is true and the request must be rejected. If another request is
// already consuming the token, the caller is a concurrent duplicate: it gets
// the leader's inflightCall to wait on. Otherwise the caller becomes the
// leader and is responsible for rotating the token and calling finish.
func (g *replayGuard) begin(token []byte) (leader bool, call *inflightCall, replay bool) {
	key := string(token)

	g.mu.Lock()
	defer g.mu.Unlock()

	if entry, ok := g.consumed[key]; ok {
		if g.now().Before(entry.expiresAt) {
			return false, nil, true
		}

		delete(g.consumed, key)
	}

	if existing, ok := g.inflight[key]; ok {
		existing.followers++
		return false, existing, false
	}

	call = &inflightCall{done: make(chan struct{})}
	g.inflight[key] = call

	return true, call, false
}

// wait blocks until the leader has finished rotating the token.
func (g *replayGuard) wait(call *inflightCall) ([]byte, error) {
	<-call.done
	return call.newToken, call.err
}

// finish is called by the leader once the wrapped handler has completed (or
// rotation failed). A nil error marks the token as consumed, shares the
// rotated token with waiting followers and closes the barrier; a non-nil error
// releases the in-flight entry without marking the token consumed so that a
// retried request is not poisoned.
func (g *replayGuard) finish(token, newToken []byte, call *inflightCall, err error) {
	key := string(token)

	g.mu.Lock()
	defer g.mu.Unlock()

	delete(g.inflight, key)

	if err == nil {
		g.consumed[key] = consumedToken{expiresAt: g.now().Add(g.ttl)}
		g.sweepLocked()
	}

	if call != nil {
		call.err = err
		if err == nil {
			call.newToken = newToken
		}
		close(call.done)
	}
}

// sweepLocked prunes expired entries and, when the consumed map still exceeds
// the size bound, evicts the entries closest to their expiry.
func (g *replayGuard) sweepLocked() {
	if len(g.consumed) <= replayGuardMaxEntries {
		return
	}

	now := g.now()
	for key, entry := range g.consumed {
		if !now.Before(entry.expiresAt) {
			delete(g.consumed, key)
		}
	}

	if len(g.consumed) <= replayGuardMaxEntries {
		return
	}

	keys := make([]string, 0, len(g.consumed))
	for key := range g.consumed {
		keys = append(keys, key)
	}

	sort.Slice(keys, func(i, j int) bool {
		return g.consumed[keys[i]].expiresAt.Before(g.consumed[keys[j]].expiresAt)
	})

	excess := len(g.consumed) - replayGuardMaxEntries
	for _, key := range keys[:excess] {
		delete(g.consumed, key)
	}
}
