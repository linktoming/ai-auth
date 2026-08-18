// Package policy decides whether an agent may perform an action.
//
// The model is deny-by-default: an identity with no matching grant cannot see
// that an item exists, let alone read it. Every constraint is evaluated on the
// server, because the agent -- which may be running attacker-controlled text --
// is not a trustworthy place to enforce anything.
package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/linktoming/ai-auth/internal/store"
)

// Request is one authorisation question.
type Request struct {
	Agent  string
	Item   string
	Action store.Action
	Fields []string
	Target string
	Reason string
	Now    time.Time
}

// Code classifies a denial so the API can pick a status code and the agent can
// react sensibly (retry later vs. never retry).
type Code string

// Denial codes.
const (
	CodeOK            Code = ""
	CodeNoGrant       Code = "no_grant"
	CodeExpiredGrant  Code = "grant_expired"
	CodeFieldDenied   Code = "field_denied"
	CodeTargetDenied  Code = "target_denied"
	CodeReasonMissing Code = "reason_required"
	CodeExhausted     Code = "grant_exhausted"
	CodeRateLimited   Code = "rate_limited"
	CodeNeedsApproval Code = "approval_required"
)

// Result is the outcome of an evaluation.
type Result struct {
	Allowed          bool
	RequiresApproval bool
	Grant            *store.Grant
	Code             Code
	Reason           string
	// RetryAfter is set for rate-limited denials.
	RetryAfter time.Duration
}

// Evaluate answers a request without mutating any state.
//
// When several grants could apply, the one that needs no human approval wins,
// so adding a broad "break glass, ask a human" grant never slows down work that
// a narrow automatic grant already covers.
func Evaluate(d *store.Data, req Request) Result {
	candidates := make([]*store.Grant, 0, 4)
	for _, g := range d.Grants {
		if g.Revoked || g.Agent != req.Agent {
			continue
		}
		if !g.Allows(req.Action) || !g.MatchesItem(req.Item) {
			continue
		}
		candidates = append(candidates, g)
	}
	// Stable order keeps denial messages deterministic across restarts.
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })

	if len(candidates) == 0 {
		return Result{Code: CodeNoGrant, Reason: fmt.Sprintf("no grant permits %s on %q", req.Action, req.Item)}
	}

	// Report the most informative outcome among the candidates. Starting from a
	// synthetic "no grant" result would hide a real grant's denial -- and the
	// caller relies on Result.Grant being set to tell "you may not" apart from
	// "there is nothing here".
	var best *Result
	for _, g := range candidates {
		res := check(d, g, req)
		if res.Allowed && !res.RequiresApproval {
			return res
		}
		if best == nil || better(res, *best) {
			best = &res
		}
	}
	return *best
}

// better ranks outcomes so the most useful one is reported: an approvable
// request beats a hard denial, and a temporary denial beats a permanent one.
func better(a, b Result) bool { return rank(a) > rank(b) }

func rank(r Result) int {
	switch {
	case r.Allowed && !r.RequiresApproval:
		return 4
	case r.Allowed && r.RequiresApproval:
		return 3
	case r.Code == CodeRateLimited || r.Code == CodeNeedsApproval:
		return 2
	case r.Code == CodeReasonMissing || r.Code == CodeFieldDenied || r.Code == CodeTargetDenied:
		return 1
	default:
		return 0
	}
}

func check(d *store.Data, g *store.Grant, req Request) Result {
	deny := func(c Code, format string, args ...any) Result {
		return Result{Grant: g, Code: c, Reason: fmt.Sprintf(format, args...)}
	}

	if g.MaxUses < 0 {
		return deny(CodeExhausted, "grant %s is disabled (negative max_uses)", g.ID)
	}
	if g.NotBefore != nil && req.Now.Before(*g.NotBefore) {
		return deny(CodeExpiredGrant, "grant %s is not valid until %s", g.ID, g.NotBefore.UTC().Format(time.RFC3339))
	}
	if g.NotAfter != nil && req.Now.After(*g.NotAfter) {
		return deny(CodeExpiredGrant, "grant %s expired at %s", g.ID, g.NotAfter.UTC().Format(time.RFC3339))
	}
	for _, f := range req.Fields {
		if !g.MatchesField(f) {
			return deny(CodeFieldDenied, "grant %s does not cover field %q", g.ID, f)
		}
	}
	if !g.MatchesTarget(req.Target) {
		return deny(CodeTargetDenied, "grant %s does not permit target %q (allowed: %s)", g.ID, req.Target, strings.Join(g.AllowedTargets, ", "))
	}
	if g.RequireReason && strings.TrimSpace(req.Reason) == "" {
		return deny(CodeReasonMissing, "grant %s requires a reason for every request", g.ID)
	}

	if c := d.Counters[g.ID]; c != nil {
		if g.MaxUses > 0 && c.TotalUses >= g.MaxUses {
			return deny(CodeExhausted, "grant %s has been used %d/%d times", g.ID, c.TotalUses, g.MaxUses)
		}
		if g.Rate != nil && g.Rate.Count > 0 {
			window := time.Duration(g.Rate.Window) * time.Second
			if req.Now.Sub(c.WindowStart) < window && c.WindowUses >= g.Rate.Count {
				retry := window - req.Now.Sub(c.WindowStart)
				r := deny(CodeRateLimited, "grant %s allows %d uses per %s; retry in %s", g.ID, g.Rate.Count, window, retry.Round(time.Second))
				r.RetryAfter = retry
				return r
			}
		}
	}

	return Result{Allowed: true, RequiresApproval: g.RequireApproval, Grant: g, Code: CodeOK}
}

// Commit records one use of a grant. It is called before the secret is
// released, so a crash between the two fails closed: the use is counted even if
// the agent never received the value.
func Commit(d *store.Data, g *store.Grant, now time.Time) {
	c := d.Counters[g.ID]
	if c == nil {
		c = &store.Counter{GrantID: g.ID, WindowStart: now}
		d.Counters[g.ID] = c
	}
	if g.Rate != nil && g.Rate.Window > 0 {
		if now.Sub(c.WindowStart) >= time.Duration(g.Rate.Window)*time.Second {
			c.WindowStart = now
			c.WindowUses = 0
		}
	}
	c.TotalUses++
	c.WindowUses++
}

// VisibleItems returns the item names an agent is allowed to know exist.
func VisibleItems(d *store.Data, agent string, now time.Time) []string {
	seen := map[string]bool{}
	for name := range d.Items {
		for _, g := range d.Grants {
			if g.Revoked || g.Agent != agent || !g.MatchesItem(name) {
				continue
			}
			if !g.Allows(store.ActionList) && !g.Allows(store.ActionRead) && !g.Allows(store.ActionTOTP) {
				continue
			}
			if g.NotAfter != nil && now.After(*g.NotAfter) {
				continue
			}
			seen[name] = true
			break
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// AllowedFields narrows a requested field list to what the grant permits and
// the item actually allows to leave the server. An empty request means "every
// field I am allowed to see".
func AllowedFields(item *store.Item, g *store.Grant, requested []string) ([]string, error) {
	if len(requested) == 0 {
		var out []string
		for _, name := range item.FieldNames() {
			if item.Releasable(name) && g.MatchesField(name) {
				out = append(out, name)
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("no releasable fields of %q are covered by grant %s", item.Name, g.ID)
		}
		return out, nil
	}
	for _, name := range requested {
		if _, ok := item.Fields[name]; !ok {
			return nil, fmt.Errorf("item %q has no field %q", item.Name, name)
		}
		if !item.Releasable(name) {
			return nil, fmt.Errorf("field %q of %q is never releasable", name, item.Name)
		}
		if !g.MatchesField(name) {
			return nil, fmt.Errorf("grant %s does not cover field %q", g.ID, name)
		}
	}
	return requested, nil
}
