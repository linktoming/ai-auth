package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/linktoming/ai-auth/internal/api"
	"github.com/linktoming/ai-auth/internal/audit"
	"github.com/linktoming/ai-auth/internal/policy"
	"github.com/linktoming/ai-auth/internal/seal"
	"github.com/linktoming/ai-auth/internal/store"
)

func (s *Server) handleWhoAmI(w http.ResponseWriter, _ *http.Request, sess *session) {
	v := s.cfg.Vault
	v.RLock()
	defer v.RUnlock()
	d := v.Data()

	resp := api.WhoAmIResponse{
		Agent:       sess.agent,
		Fingerprint: sess.fingerprint,
		Role:        string(sess.role),
		ServerID:    d.ServerID,
		ExpiresAt:   sess.expiresAt,
	}
	ids := make([]string, 0, len(d.Grants))
	for id := range d.Grants {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		g := d.Grants[id]
		if g.Revoked || g.Agent != sess.agent {
			continue
		}
		sum := api.GrantSummary{
			ID: g.ID, Items: g.Items, Fields: g.Fields, Description: g.Description,
			NotAfter: g.NotAfter, RequireApproval: g.RequireApproval,
			RequireReason: g.RequireReason, AllowedTargets: g.AllowedTargets,
		}
		for _, a := range g.Actions {
			sum.Actions = append(sum.Actions, string(a))
		}
		if g.MaxUses > 0 {
			used := 0
			if c := d.Counters[g.ID]; c != nil {
				used = c.TotalUses
			}
			left := max(g.MaxUses-used, 0)
			sum.UsesRemaining = &left
		}
		resp.Grants = append(resp.Grants, sum)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleList(w http.ResponseWriter, _ *http.Request, sess *session) {
	v := s.cfg.Vault
	v.RLock()
	defer v.RUnlock()
	d := v.Data()
	now := s.now()

	resp := api.ListResponse{Items: []api.ItemSummary{}}
	for _, name := range policy.VisibleItems(d, sess.agent, now) {
		item := d.Items[name]
		if item == nil {
			continue
		}
		sum := api.ItemSummary{
			Name: item.Name, Title: item.Title, Target: item.Target,
			Description: item.Description, HasOTP: item.OTP != nil,
			EndToEnd: item.EndToEnd, NeedsRotation: item.NeedsRotation,
		}
		// Only advertise fields the caller could actually obtain: the seed is
		// never listed, so an agent is never even tempted to ask.
		for _, f := range item.FieldNames() {
			if item.Releasable(f) {
				sum.Fields = append(sum.Fields, f)
			}
		}
		for _, action := range []store.Action{store.ActionRead, store.ActionTOTP, store.ActionList} {
			if res := policy.Evaluate(d, policy.Request{
				Agent: sess.agent, Item: item.Name, Action: action, Now: now,
			}); res.Grant != nil && res.Grant.Allows(action) {
				sum.Actions = append(sum.Actions, string(action))
			}
		}
		resp.Items = append(resp.Items, sum)
	}
	writeJSON(w, http.StatusOK, resp)
}

// authzResult carries everything a handler needs after a successful check.
type authzResult struct {
	item   *store.Item
	grant  *store.Grant
	fields []string
}

// authorize runs the shared gate in front of every secret-bearing endpoint:
// find the item, evaluate policy, resolve any approval, then charge the grant.
// It writes the response itself on failure and returns ok=false.
//
// The vault write lock must be held by the caller, because charging the grant
// and consuming the approval have to be atomic with the release that follows.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, sess *session,
	itemName string, action store.Action, wantFields []string, reason, target, approvalID string,
) (authzResult, bool) {
	d := s.cfg.Vault.Data()
	now := s.now()

	deny := func(status int, code, msg string, retry time.Duration) (authzResult, bool) {
		s.auditRecord(audit.Record{
			Actor: sess.agent, KeyID: sess.fingerprint, Action: string(action), Item: itemName,
			Fields: wantFields, Target: target, Reason: reason, Decision: audit.Deny,
			Detail: msg, Remote: remoteAddr(r),
		})
		if retry > 0 {
			writeRetryableError(w, status, code, msg, retry)
		} else {
			writeError(w, status, code, msg)
		}
		return authzResult{}, false
	}

	res := policy.Evaluate(d, policy.Request{
		Agent: sess.agent, Item: itemName, Action: action, Fields: wantFields,
		Target: target, Reason: reason, Now: now,
	})

	item := d.Items[itemName]
	if item == nil {
		// If no grant could ever match this name, answer exactly as we would
		// for a permission failure. Otherwise the endpoint becomes a way to
		// enumerate the vault's contents one guess at a time.
		if res.Grant == nil {
			return deny(http.StatusForbidden, string(policy.CodeNoGrant), res.Reason, 0)
		}
		return deny(http.StatusNotFound, "not_found", fmt.Sprintf("no item named %q", itemName), 0)
	}

	if !res.Allowed {
		status := http.StatusForbidden
		if res.Code == policy.CodeRateLimited {
			status = http.StatusTooManyRequests
		}
		return deny(status, string(res.Code), res.Reason, res.RetryAfter)
	}

	fields := wantFields
	if action == store.ActionRead {
		var err error
		fields, err = policy.AllowedFields(item, res.Grant, wantFields)
		if err != nil {
			return deny(http.StatusForbidden, string(policy.CodeFieldDenied), err.Error(), 0)
		}
	}

	if res.RequiresApproval {
		ok, msg := s.resolveApproval(w, r, sess, item.Name, action, fields, reason, target, approvalID, now)
		if !ok {
			if msg != "" {
				s.auditRecord(audit.Record{
					Actor: sess.agent, KeyID: sess.fingerprint, Action: string(action), Item: item.Name,
					Fields: fields, Target: target, Reason: reason, Decision: audit.Pending,
					Detail: msg, Remote: remoteAddr(r),
				})
			}
			return authzResult{}, false
		}
	}

	// Charge the grant before handing anything over. If the release then fails,
	// we have over-counted rather than under-counted -- the safe direction.
	policy.Commit(d, res.Grant, now)
	return authzResult{item: item, grant: res.Grant, fields: fields}, true
}

// resolveApproval either spends a matching approval or opens a new request.
func (s *Server) resolveApproval(w http.ResponseWriter, r *http.Request, sess *session,
	itemName string, action store.Action, fields []string, reason, target, approvalID string, now time.Time,
) (bool, string) {
	d := s.cfg.Vault.Data()

	if approvalID != "" {
		ap := d.Approvals[approvalID]
		switch {
		case ap == nil || !constantTimeEqual(ap.Agent, sess.agent):
			writeError(w, http.StatusForbidden, "approval_invalid", "no such approval for this identity")
			return false, "unknown approval " + approvalID
		case now.After(ap.ExpiresAt):
			ap.Status = store.ApprovalExpired
			writeError(w, http.StatusForbidden, "approval_expired", "that approval has expired; request a new one")
			return false, "approval expired"
		case ap.Status == store.ApprovalUsed:
			// Approvals are single-use so one human "yes" cannot be replayed
			// into an unbounded number of releases.
			writeError(w, http.StatusForbidden, "approval_used", "that approval has already been used")
			return false, "approval replayed"
		case ap.Status == store.ApprovalDenied:
			writeError(w, http.StatusForbidden, "approval_denied", "a human declined this request")
			return false, "approval denied by " + ap.DecidedBy
		case ap.Status != store.ApprovalApproved:
			writeJSON(w, http.StatusAccepted, api.ApprovalPendingResponse{
				ApprovalID: ap.ID, Status: string(ap.Status), ExpiresAt: ap.ExpiresAt,
				Message: "still waiting for a human decision",
			})
			return false, ""
		case !ap.Matches(sess.agent, itemName, action, fields):
			// Binding the approval to the exact request stops an approval for
			// a harmless read being spent on something else.
			writeError(w, http.StatusForbidden, "approval_mismatch",
				"that approval was issued for a different request")
			return false, "approval scope mismatch"
		}
		ap.Status = store.ApprovalUsed
		return true, ""
	}

	// Reuse a pending or approved request for the same thing rather than
	// spamming the operator with duplicates on every retry.
	for _, ap := range d.Approvals {
		if ap.Status != store.ApprovalPending && ap.Status != store.ApprovalApproved {
			continue
		}
		if now.After(ap.ExpiresAt) || !ap.Matches(sess.agent, itemName, action, fields) {
			continue
		}
		writeJSON(w, http.StatusAccepted, api.ApprovalPendingResponse{
			ApprovalID: ap.ID, Status: string(ap.Status), ExpiresAt: ap.ExpiresAt,
			Message: "a human must approve this request; retry with this approval_id",
		})
		return false, ""
	}

	id, err := randomID("apr")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not create an approval request")
		return false, ""
	}
	ap := &store.Approval{
		ID: id, Agent: sess.agent, Item: itemName, Action: action, Fields: fields,
		Target: target, Reason: reason, RequestedAt: now,
		ExpiresAt: now.Add(s.cfg.ApprovalTTL), Status: store.ApprovalPending,
	}
	d.Approvals[id] = ap
	if err := s.cfg.Vault.SaveLocked(); err != nil {
		s.cfg.Logger.Error("could not persist approval request", "error", err)
	}
	s.cfg.Logger.Info("approval requested", "agent", sess.agent, "item", itemName,
		"action", action, "approval", id, "reason", reason)
	writeJSON(w, http.StatusAccepted, api.ApprovalPendingResponse{
		ApprovalID: id, Status: string(store.ApprovalPending), ExpiresAt: ap.ExpiresAt,
		Message: "a human must approve this request; retry with this approval_id",
	})
	return false, "approval " + id + " opened"
}

func (s *Server) handleRead(w http.ResponseWriter, r *http.Request, sess *session) {
	var req api.ReadRequest
	if !decode(w, r, &req) {
		return
	}
	v := s.cfg.Vault
	v.Lock()
	defer v.Unlock()

	az, ok := s.authorize(w, r, sess, req.Item, store.ActionRead, req.Fields, req.Reason, req.Target, req.ApprovalID)
	if !ok {
		return
	}
	now := s.now()
	lease := s.newLease(sess, az.item.Name, az.fields, req.Target, req.Reason, req.TTLSeconds, now)

	resp := api.ReadResponse{
		Item: az.item.Name, LeaseID: lease.ID, ExpiresAt: lease.ExpiresAt, Fields: az.fields,
	}

	if az.item.EndToEnd {
		// The server is a courier here: it hands back ciphertext plus the data
		// key wrapped to this agent's SSH key, and never sees the values.
		wrapped := findRecipient(az.item, sess.fingerprint)
		if wrapped == nil {
			writeError(w, http.StatusForbidden, "not_a_recipient",
				"this item is end-to-end encrypted and your key is not one of its recipients")
			return
		}
		resp.EndToEnd = true
		resp.ServerID = v.Data().ServerID
		resp.WrappedKey = wrapped
		resp.Ciphertexts = map[string][]byte{}
		for _, f := range az.fields {
			resp.Ciphertexts[f] = az.item.Fields[f].Ciphertext
		}
	} else {
		payload := api.SecretPayload{Fields: map[string]string{}}
		for _, f := range az.fields {
			val, err := v.ReadField(az.item, f)
			if err != nil {
				s.cfg.Logger.Error("could not decrypt field", "item", az.item.Name, "field", f, "error", err)
				writeError(w, http.StatusInternalServerError, "internal", "could not read that field")
				return
			}
			payload.Fields[f] = val
		}
		sealed, err := s.sealPayload(sess, az.item.Name, "read", payload)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "could not seal the response")
			return
		}
		resp.Sealed = sealed
	}

	if !s.mustAudit(w, audit.Record{
		Actor: sess.agent, KeyID: sess.fingerprint, Action: string(store.ActionRead),
		Item: az.item.Name, Fields: az.fields, Target: req.Target, Reason: req.Reason,
		Decision: audit.Allow, LeaseID: lease.ID, Remote: remoteAddr(r),
		Meta: map[string]string{"grant": az.grant.ID},
	}) {
		return
	}
	s.finishRelease(az.item, lease, now)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCode(w http.ResponseWriter, r *http.Request, sess *session) {
	var req api.CodeRequest
	if !decode(w, r, &req) {
		return
	}
	v := s.cfg.Vault
	v.Lock()
	defer v.Unlock()

	az, ok := s.authorize(w, r, sess, req.Item, store.ActionTOTP, nil, req.Reason, req.Target, req.ApprovalID)
	if !ok {
		return
	}
	now := s.now()
	mint, err := v.MintOTP(az.item, now)
	if err != nil {
		s.writeMintError(w, r, sess, az.item.Name, req, err)
		return
	}

	sealed, err := s.sealPayload(sess, az.item.Name, "code", api.CodePayload{Code: mint.Code})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not seal the response")
		return
	}
	lease := s.newLease(sess, az.item.Name, []string{"code"}, req.Target, req.Reason, 0, now)

	// The code itself is never written to the audit log; only a short digest,
	// which is enough to tie a log entry to a specific code after the fact.
	if !s.mustAudit(w, audit.Record{
		Actor: sess.agent, KeyID: sess.fingerprint, Action: string(store.ActionTOTP),
		Item: az.item.Name, Target: req.Target, Reason: req.Reason, Decision: audit.Allow,
		LeaseID: lease.ID, Remote: remoteAddr(r),
		Meta: map[string]string{
			"grant":       az.grant.ID,
			"code_digest": audit.CodeDigest(az.item.Name, mint.Code, mint.Step),
			"step":        fmt.Sprint(mint.Step),
			"reused":      fmt.Sprint(mint.Reused),
		},
	}) {
		return
	}
	if err := v.SaveLocked(); err != nil {
		s.cfg.Logger.Error("could not persist mint state", "error", err)
	}

	resp := api.CodeResponse{
		Item: az.item.Name, LeaseID: lease.ID, Sealed: sealed,
		Digits: az.item.OTP.Config.Digits, ExpiresAt: mint.ExpiresAt,
		ValidForSeconds: int(mint.ValidFor.Seconds()), Reused: mint.Reused,
		Issuer: az.item.OTP.Config.Issuer, Account: az.item.OTP.Config.Account,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) writeMintError(w http.ResponseWriter, r *http.Request, sess *session, item string, req api.CodeRequest, err error) {
	s.auditRecord(audit.Record{
		Actor: sess.agent, KeyID: sess.fingerprint, Action: string(store.ActionTOTP), Item: item,
		Target: req.Target, Reason: req.Reason, Decision: audit.Deny, Detail: err.Error(),
		Remote: remoteAddr(r),
	})
	switch {
	case errors.Is(err, store.ErrMintTooSoon):
		writeRetryableError(w, http.StatusTooManyRequests, "mint_too_soon", err.Error(), 0)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "no_second_factor", err.Error())
	default:
		s.cfg.Logger.Error("mint failed", "item", item, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not compute a code")
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, sess *session) {
	var req api.LoginRequest
	if !decode(w, r, &req) {
		return
	}
	v := s.cfg.Vault
	v.Lock()
	defer v.Unlock()

	az, ok := s.authorize(w, r, sess, req.Item, store.ActionRead, nil, req.Reason, req.Target, req.ApprovalID)
	if !ok {
		return
	}
	if az.item.EndToEnd {
		writeError(w, http.StatusBadRequest, "end_to_end",
			"this item is end-to-end encrypted; use read and decrypt it locally")
		return
	}
	now := s.now()
	payload := api.LoginPayload{Fields: map[string]string{}}
	for _, f := range az.fields {
		val, err := v.ReadField(az.item, f)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "could not read that field")
			return
		}
		payload.Fields[f] = val
	}

	resp := api.LoginResponse{Item: az.item.Name, Fields: az.fields}
	meta := map[string]string{"grant": az.grant.ID}

	if req.WithCode {
		// Minting requires its own action, so a read-only grant cannot obtain a
		// code by asking for a "login" instead.
		codeRes := policy.Evaluate(v.Data(), policy.Request{
			Agent: sess.agent, Item: az.item.Name, Action: store.ActionTOTP,
			Target: req.Target, Reason: req.Reason, Now: now,
		})
		if !codeRes.Allowed || codeRes.RequiresApproval {
			writeError(w, http.StatusForbidden, string(codeRes.Code),
				"a code was requested but not permitted: "+codeRes.Reason)
			return
		}
		mint, err := v.MintOTP(az.item, now)
		if err != nil {
			s.writeMintError(w, r, sess, az.item.Name, api.CodeRequest{Reason: req.Reason, Target: req.Target}, err)
			return
		}
		policy.Commit(v.Data(), codeRes.Grant, now)
		payload.Code = mint.Code
		resp.CodeExpiresAt = mint.ExpiresAt
		resp.ValidForSeconds = int(mint.ValidFor.Seconds())
		meta["code_digest"] = audit.CodeDigest(az.item.Name, mint.Code, mint.Step)
		meta["step"] = fmt.Sprint(mint.Step)
	}

	sealed, err := s.sealPayload(sess, az.item.Name, "login", payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not seal the response")
		return
	}
	lease := s.newLease(sess, az.item.Name, az.fields, req.Target, req.Reason, req.TTLSeconds, now)
	resp.Sealed = sealed
	resp.LeaseID = lease.ID
	resp.ExpiresAt = lease.ExpiresAt

	action := "login"
	if req.WithCode {
		action = "login+code"
	}
	if !s.mustAudit(w, audit.Record{
		Actor: sess.agent, KeyID: sess.fingerprint, Action: action, Item: az.item.Name,
		Fields: az.fields, Target: req.Target, Reason: req.Reason, Decision: audit.Allow,
		LeaseID: lease.ID, Remote: remoteAddr(r), Meta: meta,
	}) {
		return
	}
	s.finishRelease(az.item, lease, now)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request, sess *session) {
	var req api.ReleaseRequest
	if !decode(w, r, &req) {
		return
	}
	v := s.cfg.Vault
	v.Lock()
	defer v.Unlock()

	lease := v.Data().Leases[req.LeaseID]
	if lease == nil || !constantTimeEqual(lease.Agent, sess.agent) {
		writeError(w, http.StatusNotFound, "not_found", "no such lease")
		return
	}
	if lease.Status == store.LeaseActive {
		now := s.now()
		lease.Status = store.LeaseReleased
		lease.ReleasedAt = &now
		s.auditRecord(audit.Record{
			Actor: sess.agent, KeyID: sess.fingerprint, Action: "release", Item: lease.Item,
			Decision: audit.Allow, LeaseID: lease.ID, Remote: remoteAddr(r),
		})
		if err := v.SaveLocked(); err != nil {
			s.cfg.Logger.Error("could not persist lease release", "error", err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"lease_id": lease.ID, "status": lease.Status})
}

// newLease records that a credential is now in an agent's hands.
func (s *Server) newLease(sess *session, item string, fields []string, target, reason string, ttlSeconds int, now time.Time) *store.Lease {
	ttl := s.cfg.LeaseTTL
	if ttlSeconds > 0 {
		ttl = time.Duration(ttlSeconds) * time.Second
	}
	ttl = min(ttl, s.cfg.MaxLeaseTTL)
	id, err := randomID("lse")
	if err != nil {
		id = "lse_unknown"
	}
	l := &store.Lease{
		ID: id, Agent: sess.agent, Item: item, Fields: fields, Target: target,
		Reason: reason, IssuedAt: now, ExpiresAt: now.Add(ttl), Status: store.LeaseActive,
	}
	s.cfg.Vault.Data().Leases[id] = l
	return l
}

// finishRelease applies post-release bookkeeping and persists.
func (s *Server) finishRelease(item *store.Item, lease *store.Lease, now time.Time) {
	if item.RotateAfterUse {
		// The value has now been outside the vault, so treat it as burned.
		item.NeedsRotation = true
	}
	s.expireLeases(now)
	if err := s.cfg.Vault.SaveLocked(); err != nil {
		s.cfg.Logger.Error("could not persist release", "lease", lease.ID, "error", err)
	}
}

func (s *Server) expireLeases(now time.Time) {
	d := s.cfg.Vault.Data()
	for id, l := range d.Leases {
		if l.Status == store.LeaseActive && now.After(l.ExpiresAt) {
			l.Status = store.LeaseExpired
		}
		// Keep the record around long enough to be useful, then drop it; the
		// audit log is the durable history, not this table.
		if l.Status != store.LeaseActive && now.Sub(l.IssuedAt) > 24*time.Hour {
			delete(d.Leases, id)
		}
	}
}

func (s *Server) sealPayload(sess *session, item, purpose string, payload any) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return sess.keys.SealToClient(raw, api.PayloadAAD(sess.id, item, purpose))
}

func findRecipient(item *store.Item, fingerprint string) *seal.WrappedKey {
	for _, w := range item.Recipients {
		if w.Fingerprint == fingerprint {
			return w
		}
	}
	return nil
}
