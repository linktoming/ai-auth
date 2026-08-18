package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/linktoming/ai-auth/internal/adminapi"
	"github.com/linktoming/ai-auth/internal/api"
	"github.com/linktoming/ai-auth/internal/audit"
	"github.com/linktoming/ai-auth/internal/otp"
	"github.com/linktoming/ai-auth/internal/sshid"
	"github.com/linktoming/ai-auth/internal/store"
)

func (s *Server) handleAdminListAgents(w http.ResponseWriter, _ *http.Request, _ *session) {
	v := s.cfg.Vault
	v.RLock()
	defer v.RUnlock()
	out := make([]*store.Agent, 0, len(v.Data().Agents))
	for _, a := range v.Data().Agents {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, http.StatusOK, map[string]any{"agents": out})
}

func (s *Server) handleAdminPutAgent(w http.ResponseWriter, r *http.Request, sess *session) {
	var req adminapi.PutAgentRequest
	if !decode(w, r, &req) {
		return
	}
	pub, comment, err := sshid.ParseAuthorizedKey(req.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_key", err.Error())
		return
	}
	role := store.Role(req.Role)
	if role != store.RoleAgent && role != store.RoleOperator {
		writeError(w, http.StatusBadRequest, "bad_role", `role must be "agent" or "operator"`)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = comment
	}
	if name == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "an agent name is required")
		return
	}

	v := s.cfg.Vault
	v.Lock()
	defer v.Unlock()
	d := v.Data()
	fp := sshid.Fingerprint(pub)

	// Names are how grants refer to identities, so two live keys must never
	// share one: revoking a name has to revoke exactly one key.
	for other, a := range d.Agents {
		if a.Name == name && other != fp {
			writeError(w, http.StatusConflict, "name_taken",
				fmt.Sprintf("agent name %q is already used by %s", name, other))
			return
		}
	}

	now := s.now()
	agent := d.Agents[fp]
	if agent == nil {
		agent = &store.Agent{Fingerprint: fp, CreatedAt: now}
		d.Agents[fp] = agent
	}
	agent.Name = name
	agent.PublicKey = sshid.MarshalAuthorizedKey(pub)
	agent.Role = role
	agent.Description = req.Description
	agent.Disabled = false
	agent.ExpiresAt = req.ExpiresAt

	if err := v.SaveLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not save the vault")
		return
	}
	s.auditRecord(audit.Record{
		Actor: sess.agent, KeyID: sess.fingerprint, Action: "admin.agent.put",
		Decision: audit.Allow, Detail: name + " " + fp, Remote: remoteAddr(r),
	})
	writeJSON(w, http.StatusOK, agent)
}

func (s *Server) handleAdminDisableAgent(w http.ResponseWriter, r *http.Request, sess *session) {
	var req adminapi.DisableAgentRequest
	if !decode(w, r, &req) {
		return
	}
	v := s.cfg.Vault
	v.Lock()
	defer v.Unlock()
	d := v.Data()

	agent := d.Agents[req.Fingerprint]
	if agent == nil {
		for _, a := range d.Agents {
			if a.Name == req.Fingerprint {
				agent = a
				break
			}
		}
	}
	if agent == nil {
		writeError(w, http.StatusNotFound, "not_found", "no such agent")
		return
	}
	agent.Disabled = true
	// Revocation must be immediate: tearing up the sessions is the difference
	// between "cannot get new secrets" and "cannot do anything".
	s.dropSessionsFor(agent.Name)
	if err := v.SaveLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not save the vault")
		return
	}
	s.auditRecord(audit.Record{
		Actor: sess.agent, KeyID: sess.fingerprint, Action: "admin.agent.disable",
		Decision: audit.Allow, Detail: agent.Name, Remote: remoteAddr(r),
	})
	writeJSON(w, http.StatusOK, agent)
}

func (s *Server) dropSessionsFor(agentName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for tok, sess := range s.sessions {
		if sess.agent == agentName {
			delete(s.sessions, tok)
		}
	}
	for id, p := range s.pending {
		if p.agent == agentName {
			delete(s.pending, id)
		}
	}
}

func (s *Server) handleAdminListItems(w http.ResponseWriter, _ *http.Request, _ *session) {
	v := s.cfg.Vault
	v.RLock()
	defer v.RUnlock()
	out := []adminapi.ItemView{}
	names := make([]string, 0, len(v.Data().Items))
	for name := range v.Data().Items {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		item := v.Data().Items[name]
		view := adminapi.ItemView{
			Name: item.Name, Title: item.Title, Target: item.Target,
			Description: item.Description, EndToEnd: item.EndToEnd,
			HasOTP: item.OTP != nil, NeedsRotation: item.NeedsRotation,
			RotateAfterUse: item.RotateAfterUse, UpdatedAt: item.UpdatedAt,
		}
		for _, f := range item.FieldNames() {
			// Show the operator that a seed exists without implying it can be
			// fetched: it is listed as sealed rather than as a field.
			if f == store.SeedField {
				view.Sealed = append(view.Sealed, f)
				continue
			}
			view.Fields = append(view.Fields, f)
		}
		for _, rec := range item.Recipients {
			view.Recipients = append(view.Recipients, rec.Fingerprint)
		}
		if item.OTP != nil {
			view.OTP = &adminapi.OTPView{
				Algorithm: string(item.OTP.Config.Algorithm), Digits: item.OTP.Config.Digits,
				Period: item.OTP.Config.Period, Issuer: item.OTP.Config.Issuer,
				Account: item.OTP.Config.Account, HOTP: item.OTP.Config.HOTP,
				MinInterval: item.OTP.MinInterval, MintCount: item.OTP.MintCount,
			}
		}
		out = append(out, view)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) handleAdminPutItem(w http.ResponseWriter, r *http.Request, sess *session) {
	var req adminapi.PutItemRequest
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "an item name is required")
		return
	}

	v := s.cfg.Vault
	v.Lock()
	defer v.Unlock()
	if v.SealedLocked() {
		writeError(w, http.StatusServiceUnavailable, "sealed", "the vault is sealed")
		return
	}
	d := v.Data()

	// Secret material arrives sealed under the session keys, so it is never a
	// plaintext JSON field in transit or in an intermediary's logs.
	var payload adminapi.ItemSecrets
	if len(req.Sealed) > 0 {
		raw, err := sess.keys.OpenFromClient(req.Sealed, api.PayloadAAD(sess.id, req.Name, "put-item"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_sealed_payload", "could not open the sealed payload")
			return
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			writeError(w, http.StatusBadRequest, "bad_sealed_payload", "sealed payload is not valid JSON")
			return
		}
	}

	item := d.Items[req.Name]
	var dek []byte
	var err error
	if item == nil {
		item, dek, err = v.NewItem(req.Name)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		item.EndToEnd = req.EndToEnd
		if req.EndToEnd {
			// Nothing the server holds can open this item, so it must not keep
			// a data key it could be compelled to use.
			item.WrappedDEK = nil
			dek = nil
		}
		d.Items[req.Name] = item
	} else if item.EndToEnd != req.EndToEnd {
		writeError(w, http.StatusConflict, "mode_change",
			"an item cannot be switched between server-side and end-to-end; delete and recreate it")
		return
	} else if !item.EndToEnd {
		if dek, err = v.ItemDEK(item); err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "could not open the item")
			return
		}
	}

	if item.EndToEnd {
		if len(req.Recipients) > 0 {
			item.Recipients = req.Recipients
		}
		if len(item.Recipients) == 0 {
			writeError(w, http.StatusBadRequest, "no_recipients",
				"an end-to-end item needs at least one recipient, or nobody could ever read it")
			return
		}
		now := s.now()
		for name, ct := range req.Ciphertexts {
			if name == store.SeedField {
				writeError(w, http.StatusBadRequest, "reserved_field",
					fmt.Sprintf("%q is reserved", store.SeedField))
				return
			}
			item.Fields[name] = &store.Field{Ciphertext: ct, Releasable: true, UpdatedAt: now}
		}
	}

	if req.Title != "" {
		item.Title = req.Title
	}
	if req.Target != "" {
		item.Target = req.Target
	}
	if req.Description != "" {
		item.Description = req.Description
	}
	if req.RotateAfterUse != nil {
		item.RotateAfterUse = *req.RotateAfterUse
	}
	if req.ClearRotationFlag {
		item.NeedsRotation = false
		now := s.now()
		item.RotatedAt = &now
	}

	for name, value := range payload.Fields {
		if item.EndToEnd {
			writeError(w, http.StatusBadRequest, "end_to_end",
				"this item is end-to-end encrypted; send ciphertexts, not plaintext")
			return
		}
		if name == store.SeedField {
			writeError(w, http.StatusBadRequest, "reserved_field",
				fmt.Sprintf("%q is reserved; supply a second factor via otp_seed instead", store.SeedField))
			return
		}
		if err := v.SetField(item, dek, name, value, true); err != nil {
			writeError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	}
	for _, name := range req.RemoveFields {
		delete(item.Fields, name)
	}

	if payload.OTPSeed != "" || payload.OTPURI != "" {
		if item.EndToEnd {
			writeError(w, http.StatusBadRequest, "end_to_end",
				"the server cannot mint codes for an end-to-end item, so it will not store a seed for one")
			return
		}
		if err := s.setOTP(v, item, dek, req, payload); err != nil {
			writeError(w, http.StatusBadRequest, "bad_otp", err.Error())
			return
		}
	} else if item.OTP != nil && req.OTP != nil {
		applyOTPTuning(item, req.OTP)
	}
	if req.RemoveOTP {
		item.OTP = nil
		delete(item.Fields, store.SeedField)
	}

	item.Version++
	item.UpdatedAt = s.now()
	if err := v.SaveLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not save the vault")
		return
	}

	fields := make([]string, 0, len(payload.Fields))
	for name := range payload.Fields {
		fields = append(fields, name)
	}
	sort.Strings(fields)
	s.auditRecord(audit.Record{
		Actor: sess.agent, KeyID: sess.fingerprint, Action: "admin.item.put", Item: item.Name,
		Fields: fields, Decision: audit.Allow, Remote: remoteAddr(r),
		Meta: map[string]string{"has_otp": strconv.FormatBool(item.OTP != nil)},
	})
	writeJSON(w, http.StatusOK, map[string]any{"item": item.Name, "version": item.Version})
}

func (s *Server) setOTP(v *store.Vault, item *store.Item, dek []byte, req adminapi.PutItemRequest, payload adminapi.ItemSecrets) error {
	var seed string
	cfg := &otp.Config{}

	if payload.OTPURI != "" {
		raw, parsed, err := otp.ParseURI(payload.OTPURI)
		if err != nil {
			return err
		}
		seed, cfg = otp.EncodeSecret(raw), parsed
	} else {
		raw, err := otp.DecodeSecret(payload.OTPSeed)
		if err != nil {
			return err
		}
		seed = otp.EncodeSecret(raw)
	}
	if req.OTP != nil {
		if req.OTP.Algorithm != "" {
			cfg.Algorithm = otp.Algorithm(req.OTP.Algorithm)
		}
		if req.OTP.Digits != 0 {
			cfg.Digits = req.OTP.Digits
		}
		if req.OTP.Period != 0 {
			cfg.Period = req.OTP.Period
		}
		if req.OTP.Issuer != "" {
			cfg.Issuer = req.OTP.Issuer
		}
		if req.OTP.Account != "" {
			cfg.Account = req.OTP.Account
		}
		cfg.HOTP = cfg.HOTP || req.OTP.HOTP
	}
	if err := cfg.Normalize(); err != nil {
		return err
	}
	// The seed is written as a non-releasable field: no API path returns it.
	if err := v.SetField(item, dek, store.SeedField, seed, false); err != nil {
		return err
	}
	item.OTP = &store.OTPSpec{Config: cfg, MinInterval: 25}
	if req.OTP != nil {
		applyOTPTuning(item, req.OTP)
	}
	return nil
}

func applyOTPTuning(item *store.Item, in *adminapi.OTPView) {
	if in.MinInterval > 0 {
		item.OTP.MinInterval = in.MinInterval
	}
	if in.MinInterval < 0 {
		item.OTP.MinInterval = 0
	}
}

func (s *Server) handleAdminDeleteItem(w http.ResponseWriter, r *http.Request, sess *session) {
	var req adminapi.DeleteItemRequest
	if !decode(w, r, &req) {
		return
	}
	v := s.cfg.Vault
	v.Lock()
	defer v.Unlock()
	if _, ok := v.Data().Items[req.Name]; !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such item")
		return
	}
	delete(v.Data().Items, req.Name)
	if err := v.SaveLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not save the vault")
		return
	}
	s.auditRecord(audit.Record{
		Actor: sess.agent, KeyID: sess.fingerprint, Action: "admin.item.delete", Item: req.Name,
		Decision: audit.Allow, Remote: remoteAddr(r),
	})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": req.Name})
}

func (s *Server) handleAdminListGrants(w http.ResponseWriter, _ *http.Request, _ *session) {
	v := s.cfg.Vault
	v.RLock()
	defer v.RUnlock()
	d := v.Data()
	ids := make([]string, 0, len(d.Grants))
	for id := range d.Grants {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]adminapi.GrantView, 0, len(ids))
	for _, id := range ids {
		g := d.Grants[id]
		view := adminapi.GrantView{Grant: g}
		if c := d.Counters[id]; c != nil {
			view.TotalUses = c.TotalUses
		}
		out = append(out, view)
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": out})
}

func (s *Server) handleAdminPutGrant(w http.ResponseWriter, r *http.Request, sess *session) {
	var req adminapi.PutGrantRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.Items) == 0 || len(req.Actions) == 0 || req.Agent == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "agent, items and actions are all required")
		return
	}
	actions := make([]store.Action, 0, len(req.Actions))
	for _, a := range req.Actions {
		action := store.Action(a)
		switch action {
		case store.ActionRead, store.ActionTOTP, store.ActionList:
			actions = append(actions, action)
		default:
			writeError(w, http.StatusBadRequest, "bad_action",
				fmt.Sprintf("unknown action %q (want read, totp or list)", a))
			return
		}
	}

	v := s.cfg.Vault
	v.Lock()
	defer v.Unlock()
	d := v.Data()

	known := false
	for _, a := range d.Agents {
		if a.Name == req.Agent {
			known = true
			break
		}
	}
	if !known {
		writeError(w, http.StatusBadRequest, "unknown_agent",
			fmt.Sprintf("no agent named %q is enrolled", req.Agent))
		return
	}

	id := req.ID
	if id == "" {
		var err error
		if id, err = randomID("gr"); err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "could not create a grant")
			return
		}
	}
	g := &store.Grant{
		ID: id, Agent: req.Agent, Items: req.Items, Fields: req.Fields, Actions: actions,
		Description: req.Description, NotBefore: req.NotBefore, NotAfter: req.NotAfter,
		MaxUses: req.MaxUses, RequireApproval: req.RequireApproval,
		RequireReason: req.RequireReason, AllowedTargets: req.AllowedTargets,
		CreatedAt: s.now(), CreatedBy: sess.agent,
	}
	if req.RateCount > 0 && req.RateWindow > 0 {
		g.Rate = &store.RateLimit{Count: req.RateCount, Window: req.RateWindow}
	}
	d.Grants[id] = g
	// Re-issuing a grant id resets its budget; otherwise "give it 5 more uses"
	// would be impossible without inventing a new id.
	delete(d.Counters, id)

	if err := v.SaveLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not save the vault")
		return
	}
	s.auditRecord(audit.Record{
		Actor: sess.agent, KeyID: sess.fingerprint, Action: "admin.grant.put",
		Decision: audit.Allow, Detail: fmt.Sprintf("%s -> %s %v", req.Agent, strings.Join(req.Items, ","), req.Actions),
		Remote: remoteAddr(r), Meta: map[string]string{"grant": id},
	})
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) handleAdminRevokeGrant(w http.ResponseWriter, r *http.Request, sess *session) {
	var req adminapi.RevokeGrantRequest
	if !decode(w, r, &req) {
		return
	}
	v := s.cfg.Vault
	v.Lock()
	defer v.Unlock()
	g := v.Data().Grants[req.ID]
	if g == nil {
		writeError(w, http.StatusNotFound, "not_found", "no such grant")
		return
	}
	g.Revoked = true
	if err := v.SaveLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not save the vault")
		return
	}
	s.auditRecord(audit.Record{
		Actor: sess.agent, KeyID: sess.fingerprint, Action: "admin.grant.revoke",
		Decision: audit.Allow, Remote: remoteAddr(r), Meta: map[string]string{"grant": g.ID},
	})
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) handleAdminListApprovals(w http.ResponseWriter, r *http.Request, _ *session) {
	v := s.cfg.Vault
	v.RLock()
	defer v.RUnlock()
	wantPending := r.URL.Query().Get("status") == "pending"
	now := s.now()
	out := []*store.Approval{}
	for _, ap := range v.Data().Approvals {
		if wantPending && (ap.Status != store.ApprovalPending || now.After(ap.ExpiresAt)) {
			continue
		}
		out = append(out, ap)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RequestedAt.After(out[j].RequestedAt) })
	writeJSON(w, http.StatusOK, map[string]any{"approvals": out})
}

func (s *Server) handleAdminDecideApproval(w http.ResponseWriter, r *http.Request, sess *session) {
	var req adminapi.DecideApprovalRequest
	if !decode(w, r, &req) {
		return
	}
	v := s.cfg.Vault
	v.Lock()
	defer v.Unlock()

	ap := v.Data().Approvals[req.ID]
	if ap == nil {
		writeError(w, http.StatusNotFound, "not_found", "no such approval")
		return
	}
	now := s.now()
	if now.After(ap.ExpiresAt) {
		ap.Status = store.ApprovalExpired
		writeError(w, http.StatusConflict, "expired", "that request has already expired")
		return
	}
	if ap.Status != store.ApprovalPending {
		writeError(w, http.StatusConflict, "already_decided",
			fmt.Sprintf("that request is already %s", ap.Status))
		return
	}
	if req.Approve {
		ap.Status = store.ApprovalApproved
	} else {
		ap.Status = store.ApprovalDenied
	}
	ap.DecidedBy = sess.agent
	ap.DecidedAt = &now
	ap.Note = req.Note
	if req.ExtendSeconds > 0 {
		ap.ExpiresAt = now.Add(time.Duration(req.ExtendSeconds) * time.Second)
	}
	if err := v.SaveLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not save the vault")
		return
	}
	s.auditRecord(audit.Record{
		Actor: sess.agent, KeyID: sess.fingerprint, Action: "admin.approval.decide",
		Item: ap.Item, Decision: audit.Allow, Detail: string(ap.Status),
		Remote: remoteAddr(r), Meta: map[string]string{"approval": ap.ID, "for_agent": ap.Agent},
	})
	writeJSON(w, http.StatusOK, ap)
}

func (s *Server) handleAdminListLeases(w http.ResponseWriter, _ *http.Request, _ *session) {
	v := s.cfg.Vault
	v.Lock()
	defer v.Unlock()
	s.expireLeases(s.now())
	out := []*store.Lease{}
	for _, l := range v.Data().Leases {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt.After(out[j].IssuedAt) })
	writeJSON(w, http.StatusOK, map[string]any{"leases": out})
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request, _ *session) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = min(n, 10000)
		}
	}
	records, verifyErr := audit.VerifyFile(s.cfg.AuditPath)
	if len(records) > limit {
		records = records[len(records)-limit:]
	}
	body := map[string]any{"records": records, "chain_valid": verifyErr == nil}
	if verifyErr != nil {
		body["chain_error"] = verifyErr.Error()
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) handleAdminRecipients(w http.ResponseWriter, _ *http.Request, _ *session) {
	v := s.cfg.Vault
	v.RLock()
	defer v.RUnlock()
	out := adminapi.RecipientsResponse{Recipients: map[string]string{}}
	for fp, a := range v.Data().Agents {
		if a.Disabled {
			continue
		}
		out.Recipients[fp] = a.PublicKey
	}
	writeJSON(w, http.StatusOK, out)
}
