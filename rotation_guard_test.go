package csrf

import (
	"errors"
	"testing"
	"time"
)

var errTestRotation = errors.New("test rotation error")

func TestReplayGuardExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	guard := newReplayGuard(time.Minute)
	guard.now = func() time.Time { return now }

	token := []byte("0123456789abcdef0123456789abcdef")

	leader, call, replay := guard.begin(token)
	if !leader || call == nil || replay {
		t.Fatalf("first begin should elect a leader: got leader=%v call=%v replay=%v",
			leader, call, replay)
	}

	rotated := []byte("fedcba9876543210fedcba9876543210")
	guard.finish(token, rotated, call, nil)

	if _, _, replay := guard.begin(token); !replay {
		t.Fatalf("token should be rejected as a replay before its TTL expires")
	}

	// After the TTL elapses the stale entry is treated as expired and a new
	// leader may consume the token again.
	now = now.Add(time.Minute + time.Second)
	leader, call, replay = guard.begin(token)
	if !leader || replay {
		t.Fatalf("expired token should be consumable again: got leader=%v replay=%v",
			leader, replay)
	}
	guard.finish(token, rotated, call, nil)
}

func TestReplayGuardInFlightDuplicates(t *testing.T) {
	guard := newReplayGuard(time.Minute)
	token := []byte("0123456789abcdef0123456789abcdef")

	leader, leaderCall, replay := guard.begin(token)
	if !leader || replay {
		t.Fatalf("first begin should elect a leader: got leader=%v replay=%v", leader, replay)
	}

	for i := 0; i < 3; i++ {
		duplicateLeader, duplicateCall, duplicateReplay := guard.begin(token)
		if duplicateLeader || duplicateReplay || duplicateCall != leaderCall {
			t.Fatalf("concurrent duplicate %d should join the leader barrier", i)
		}
	}

	rotated := []byte("fedcba9876543210fedcba9876543210")
	guard.finish(token, rotated, leaderCall, nil)

	got, err := guard.wait(leaderCall)
	if err != nil {
		t.Fatalf("wait returned an unexpected error: %v", err)
	}

	if string(got) != string(rotated) {
		t.Fatalf("followers did not receive the rotated token: got %x want %x", got, rotated)
	}

	if _, _, replay := guard.begin(token); !replay {
		t.Fatalf("token should be rejected as a replay after finish")
	}
}

func TestReplayGuardFailedRotationNotConsumed(t *testing.T) {
	guard := newReplayGuard(time.Minute)
	token := []byte("0123456789abcdef0123456789abcdef")

	leader, call, replay := guard.begin(token)
	if !leader || replay {
		t.Fatalf("first begin should elect a leader")
	}

	guard.finish(token, nil, call, errTestRotation)

	leader, call, replay = guard.begin(token)
	if !leader || replay {
		t.Fatalf("a token whose rotation failed must remain usable: got leader=%v replay=%v",
			leader, replay)
	}
	guard.finish(token, []byte("new"), call, nil)
}

func TestReplayGuardEviction(t *testing.T) {
	guard := newReplayGuard(time.Hour)

	for i := 0; i < replayGuardMaxEntries+4; i++ {
		token := make([]byte, tokenLength)
		token[0] = byte(i)
		token[1] = byte(i >> 8)
		token[2] = byte(i >> 16)

		_, call, replay := guard.begin(token)
		if replay {
			t.Fatalf("fresh token %d unexpectedly treated as replay", i)
		}

		guard.finish(token, token, call, nil)
	}

	guard.mu.Lock()
	defer guard.mu.Unlock()

	if len(guard.consumed) != replayGuardMaxEntries {
		t.Fatalf("consumed map not bounded: got %d want %d",
			len(guard.consumed), replayGuardMaxEntries)
	}
}
