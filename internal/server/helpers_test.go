package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// post drives the raw HTTP API, for the cases where the client library would
// hide the very behaviour under test (replay, expiry, malformed input).
func post(t *testing.T, h *harness, path, token string, body, out any, wantStatus int) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, h.httpSrv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.httpSrv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("POST %s: status %d, want %d: %s", path, resp.StatusCode, wantStatus, payload)
	}
	if out != nil {
		if err := json.Unmarshal(payload, out); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
	}
}
