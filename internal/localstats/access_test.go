package localstats

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/model"
)

func TestAccessAggregates(t *testing.T) {
	a := newAccessAgg()
	t0 := time.Unix(1_700_000_000, 0)
	recs := []model.AccessRecord{
		{UserID: 1, DestHost: "A.com", Upload: 100, Download: 900},
		{UserID: 1, DestHost: "a.com", Upload: 10, Download: 10},
		{UserID: 2, DestHost: "b.com", Upload: 1, Download: 1, Reason: "i/o timeout"},
		{UserID: 2, DestHost: "b.com", Upload: 1, Download: 1},
		{UserID: 2, DestHost: "b.com", Upload: 1, Download: 1},
		{UserID: 3, DestHost: "c.com", ACLAction: "deny", ACLMode: "enforce"}, // ACL verdicts are not traffic
		{UserID: 3, DestHost: ""},
	}
	orig := append([]model.AccessRecord(nil), recs...)
	a.add(t0, recs)
	if !reflect.DeepEqual(recs, orig) {
		t.Fatal("records were modified: the panel push must see them unchanged")
	}
	r := a.report(t0, true, 10)
	if r.Records != 5 || len(r.ByBytes) != 2 || r.ByBytes[0].Host != "a.com" || r.ByBytes[0].Bytes != 1020 || r.ByBytes[0].Count != 2 {
		t.Fatalf("by bytes: %+v", r)
	}
	if r.ByCount[0].Host != "b.com" || r.ByCount[0].Count != 3 || r.ByCount[0].Fails != 1 {
		t.Fatalf("by count: %+v", r.ByCount)
	}
	since, hs := a.user(2, 10)
	if since != t0.Unix() || len(hs) != 1 || hs[0].Host != "b.com" || hs[0].Up != 3 {
		t.Fatalf("user 2: %d %+v", since, hs)
	}
	if _, hs := a.user(99, 10); len(hs) != 0 {
		t.Fatalf("unknown user: %+v", hs)
	}
}

func TestAccessBounded(t *testing.T) {
	a := newAccessAgg()
	t0 := time.Unix(1_700_000_000, 0)
	var recs []model.AccessRecord
	for i := 0; i < 3*maxHosts; i++ {
		recs = append(recs, model.AccessRecord{UserID: i % (maxUsers * 2), DestHost: fmt.Sprintf("h%d.example", i), Download: int64(i)})
	}
	for i := 0; i < 200; i++ { // one user touching many hosts
		recs = append(recs, model.AccessRecord{UserID: 1, DestHost: fmt.Sprintf("u%d.example", i), Download: int64(i)})
	}
	a.add(t0, recs)
	g := a.cur
	if len(g.hosts) > maxHosts || len(g.users) > maxUsers {
		t.Fatalf("hosts %d users %d", len(g.hosts), len(g.users))
	}
	for uid, hs := range g.users {
		if len(hs) > maxUserHosts {
			t.Fatalf("user %d has %d hosts", uid, len(hs))
		}
	}
	// The biggest destinations survive pruning.
	if r := a.report(t0, true, 1); r.ByBytes[0].Host != fmt.Sprintf("h%d.example", 3*maxHosts-1) {
		t.Fatalf("top after prune: %+v", r.ByBytes)
	}
}

func TestAccessRotation(t *testing.T) {
	a := newAccessAgg()
	t0 := time.Unix(1_700_000_000, 0)
	a.add(t0, []model.AccessRecord{{UserID: 1, DestHost: "old.com", Download: 5}})
	a.add(t0.Add(accessGenSpan), []model.AccessRecord{{UserID: 1, DestHost: "new.com", Download: 5}})
	if r := a.report(t0.Add(accessGenSpan), true, 10); len(r.ByBytes) != 2 || r.Since != t0.Unix() {
		t.Fatalf("both generations: %+v", r)
	}
	// One more span: the oldest generation drops out.
	r := a.report(t0.Add(2*accessGenSpan), true, 10)
	if len(r.ByBytes) != 1 || r.ByBytes[0].Host != "new.com" {
		t.Fatalf("after rotation: %+v", r)
	}
	// Idle for days: nothing stale is shown.
	if r := a.report(t0.Add(10*accessGenSpan), true, 10); len(r.ByBytes) != 0 {
		t.Fatalf("stale data: %+v", r)
	}
}
