package policy

import (
	"testing"
	"time"

	"github.com/linktoming/ai-auth/internal/store"
)

func data(grants ...*store.Grant) *store.Data {
	d := &store.Data{
		Items:    map[string]*store.Item{"prod/db": {Name: "prod/db"}},
		Grants:   map[string]*store.Grant{},
		Counters: map[string]*store.Counter{},
	}
	for _, g := range grants {
		d.Grants[g.ID] = g
	}
	return d
}

func TestDenyByDefault(t *testing.T) {
	res := Evaluate(data(), Request{Agent: "bot", Item: "prod/db", Action: store.ActionRead, Now: time.Now()})
	if res.Allowed || res.Code != CodeNoGrant {
		t.Fatalf("an agent with no grants must be denied, got %+v", res)
	}
}

func TestGrantsAreNotSharedBetweenAgents(t *testing.T) {
	d := data(&store.Grant{ID: "g1", Agent: "other", Items: []string{"*"}, Actions: []store.Action{store.ActionRead}})
	res := Evaluate(d, Request{Agent: "bot", Item: "prod/db", Action: store.ActionRead, Now: time.Now()})
	if res.Allowed {
		t.Fatal("one agent's grant must not authorise another")
	}
}

func TestRevokedAndExpiredGrants(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	for name, g := range map[string]*store.Grant{
		"revoked": {ID: "g", Agent: "bot", Items: []string{"*"}, Actions: []store.Action{store.ActionRead}, Revoked: true},
		"expired": {ID: "g", Agent: "bot", Items: []string{"*"}, Actions: []store.Action{store.ActionRead}, NotAfter: &past},
		"future":  {ID: "g", Agent: "bot", Items: []string{"*"}, Actions: []store.Action{store.ActionRead}, NotBefore: &future},
	} {
		res := Evaluate(data(g), Request{Agent: "bot", Item: "prod/db", Action: store.ActionRead, Now: now})
		if res.Allowed {
			t.Errorf("%s grant must not authorise anything", name)
		}
	}
}

// A grant that needs no approval should win over one that does, so adding a
// break-glass grant never slows down routine work.
func TestAutomaticGrantWinsOverApprovalGrant(t *testing.T) {
	now := time.Now().UTC()
	d := data(
		&store.Grant{ID: "g_auto", Agent: "bot", Items: []string{"prod/*"},
			Actions: []store.Action{store.ActionRead}},
		&store.Grant{ID: "g_gated", Agent: "bot", Items: []string{"*"},
			Actions: []store.Action{store.ActionRead}, RequireApproval: true},
	)
	res := Evaluate(d, Request{Agent: "bot", Item: "prod/db", Action: store.ActionRead, Now: now})
	if !res.Allowed || res.RequiresApproval || res.Grant.ID != "g_auto" {
		t.Fatalf("expected the automatic grant to win, got %+v", res)
	}
}

func TestRateLimitWindowRolls(t *testing.T) {
	now := time.Now().UTC()
	g := &store.Grant{ID: "g", Agent: "bot", Items: []string{"*"},
		Actions: []store.Action{store.ActionRead},
		Rate:    &store.RateLimit{Count: 2, Window: 60}}
	d := data(g)
	req := Request{Agent: "bot", Item: "prod/db", Action: store.ActionRead, Now: now}

	for i := range 2 {
		res := Evaluate(d, req)
		if !res.Allowed {
			t.Fatalf("use %d should be allowed: %s", i, res.Reason)
		}
		Commit(d, g, now)
	}
	res := Evaluate(d, req)
	if res.Allowed || res.Code != CodeRateLimited {
		t.Fatalf("the third use inside the window must be rate limited, got %+v", res)
	}
	if res.RetryAfter <= 0 || res.RetryAfter > time.Minute {
		t.Fatalf("retry-after should point inside the window, got %s", res.RetryAfter)
	}

	// Once the window rolls, the budget is fresh again.
	later := now.Add(61 * time.Second)
	req.Now = later
	if res := Evaluate(d, req); !res.Allowed {
		t.Fatalf("the window should have rolled: %s", res.Reason)
	}
}

func TestMaxUsesIsAbsolute(t *testing.T) {
	now := time.Now().UTC()
	g := &store.Grant{ID: "g", Agent: "bot", Items: []string{"*"},
		Actions: []store.Action{store.ActionRead}, MaxUses: 1}
	d := data(g)
	req := Request{Agent: "bot", Item: "prod/db", Action: store.ActionRead, Now: now}

	if res := Evaluate(d, req); !res.Allowed {
		t.Fatal("the first use should be allowed")
	}
	Commit(d, g, now)

	// Unlike a rate limit, this never comes back, however long we wait.
	req.Now = now.Add(365 * 24 * time.Hour)
	res := Evaluate(d, req)
	if res.Allowed || res.Code != CodeExhausted {
		t.Fatalf("an exhausted grant must stay exhausted, got %+v", res)
	}
}

func TestAllowedFieldsFiltersUnreleasableAndUngranted(t *testing.T) {
	item := &store.Item{Name: "prod/db", Fields: map[string]*store.Field{
		"username":      {Releasable: true},
		"password":      {Releasable: true},
		store.SeedField: {Releasable: false},
	}}
	g := &store.Grant{ID: "g", Fields: []string{"username"}}

	got, err := AllowedFields(item, g, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "username" {
		t.Fatalf("an unqualified read should return only granted fields, got %v", got)
	}
	if _, err := AllowedFields(item, g, []string{"password"}); err == nil {
		t.Fatal("an ungranted field must be refused")
	}
	if _, err := AllowedFields(item, &store.Grant{ID: "g2"}, []string{store.SeedField}); err == nil {
		t.Fatal("a non-releasable field must be refused even by an unrestricted grant")
	}
	// An unrestricted grant sees every releasable field, but never the seed.
	all, err := AllowedFields(item, &store.Grant{ID: "g2"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range all {
		if f == store.SeedField {
			t.Fatal("the seed leaked into an unqualified read")
		}
	}
	if len(all) != 2 {
		t.Fatalf("expected both releasable fields, got %v", all)
	}
}

func TestVisibleItemsRespectsGrants(t *testing.T) {
	now := time.Now().UTC()
	d := data(&store.Grant{ID: "g", Agent: "bot", Items: []string{"prod/*"},
		Actions: []store.Action{store.ActionList}})
	d.Items["staging/db"] = &store.Item{Name: "staging/db"}

	got := VisibleItems(d, "bot", now)
	if len(got) != 1 || got[0] != "prod/db" {
		t.Fatalf("visible items = %v, want [prod/db]", got)
	}
	if len(VisibleItems(d, "someone-else", now)) != 0 {
		t.Fatal("an agent with no grants must see nothing")
	}
}
