package vless

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func newTestInbound() *Inbound {
	return &Inbound{
		userEntries: make(map[int]*userEntry),
		userIDByKey: make(map[string]int),
	}
}

func TestApplyUsersStableIDsAndLimiterReuse(t *testing.T) {
	h := newTestInbound()

	ids, uuids, _ := h.applyUsersLocked([]option.VLESSUser{
		{UUID: "uuid-a", Name: "a", SpeedLimit: 100},
		{UUID: "uuid-b", Name: "b"},
	})
	if len(ids) != 2 || uuids[0] != "uuid-a" || uuids[1] != "uuid-b" {
		t.Fatalf("unexpected initial table: ids=%v uuids=%v", ids, uuids)
	}
	idA := h.userIDByKey["uuid-a"]
	limiterA := h.userEntries[idA].limiter
	if limiterA == nil {
		t.Fatal("user a should have a limiter")
	}
	if h.userEntries[h.userIDByKey["uuid-b"]].limiter != nil {
		t.Fatal("user b should not have a limiter")
	}

	// Re-apply: drop b, keep a with a new rate, add c.
	ids2, _, _ := h.applyUsersLocked([]option.VLESSUser{
		{UUID: "uuid-c", Name: "c"},
		{UUID: "uuid-a", Name: "a", SpeedLimit: 200},
	})
	if len(ids2) != 2 {
		t.Fatalf("unexpected second table: ids=%v", ids2)
	}
	if got := h.userIDByKey["uuid-a"]; got != idA {
		t.Fatalf("user a should keep stable ID %d, got %d", idA, got)
	}
	if h.userEntries[idA].limiter != limiterA {
		t.Fatal("user a's limiter instance should be reused so live connections pick up the new rate")
	}
	if _, removed := h.userIDByKey["uuid-b"]; removed {
		t.Fatal("user b should be removed")
	}
	idC := h.userIDByKey["uuid-c"]
	if idC == idA {
		t.Fatal("new user must not reuse another user's ID")
	}
	if _, ok := h.userEntries[idC]; !ok {
		t.Fatal("user c entry missing")
	}

	// Removing the speed limit drops the limiter.
	h.applyUsersLocked([]option.VLESSUser{{UUID: "uuid-a", Name: "a"}})
	if h.userEntries[idA].limiter != nil {
		t.Fatal("limiter should be dropped when speed_limit is removed")
	}
}
