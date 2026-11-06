package executor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type codexOutcomeTransport func(*http.Request) (*http.Response, error)

func (f codexOutcomeTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestCodexRefreshUnknownOutcomePersistsAndProtectsPartitions(t *testing.T) {
	var calls atomic.Int32
	originalTransport := http.DefaultTransport
	http.DefaultTransport = codexOutcomeTransport(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		if errParse := req.ParseForm(); errParse != nil {
			t.Fatal(errParse)
		}
		body := `{"access_token":`
		if req.Form.Get("client_id") != codexauth.ClientID {
			body = `{"access_token":"siwc-new","refresh_token":"siwc-next","scope":"chatgpt.tokens.use.direct","expires_in":3600}`
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	path := filepath.Join(t.TempDir(), "codex.json")
	token := path + "-refresh"
	auth := &cliproxyauth.Auth{
		ID: "codex.json", FileName: "codex.json", Provider: "codex",
		Attributes: map[string]string{cliproxyauth.AttributePath: path},
		Metadata: map[string]any{
			"type": "codex", "access_token": "outer-working", "refresh_token": token,
			"expired": time.Now().Add(time.Hour).Format(time.RFC3339), "use_siwc": true,
			"siwc": map[string]any{"access_token": "siwc-old", "refresh_token": token + "-siwc", "client_id": "siwc-client"},
		},
	}
	if errWrite := codexauth.WriteJSONFileAtomic(path, auth.Metadata); errWrite != nil {
		t.Fatal(errWrite)
	}
	executor := NewCodexExecutor(&config.Config{})
	updated, errRefresh := executor.Refresh(cliproxyauth.WithForceRefresh(context.Background()), auth.Clone())
	if errRefresh != nil {
		t.Fatalf("partial refresh failed: %v", errRefresh)
	}
	if calls.Load() != 2 || updated.Metadata["access_token"] != "outer-working" || codexauth.RefreshOutcomeUnknown(updated.Metadata, false) == nil {
		t.Fatalf("partial refresh lost active token or uncertainty: calls=%d", calls.Load())
	}
	if !updated.CodexRefreshPatch.RefreshedSIWC() || updated.CodexRefreshPatch.RefreshedOuter() {
		t.Fatal("partial refresh changed the wrong credential partition")
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	disk := ojson.ParseBytes(raw).Value().(map[string]any)
	if codexauth.RefreshOutcomeUnknown(disk, false) == nil || disk["siwc"].(map[string]any)["access_token"] != "siwc-new" {
		t.Fatal("disk did not retain both the unknown outer outcome and successful SIWC refresh")
	}
}

func TestCodexRefreshPersistedUnknownOutcomeBlocksFreshExecutor(t *testing.T) {
	var calls atomic.Int32
	originalTransport := http.DefaultTransport
	http.DefaultTransport = codexOutcomeTransport(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req,
			Body: io.NopCloser(strings.NewReader(`{"access_token":"recovered","refresh_token":"next","expires_in":3600}`))}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	path := filepath.Join(t.TempDir(), "persisted.json")
	auth := &cliproxyauth.Auth{
		ID: "persisted.json", FileName: "persisted.json", Provider: "codex",
		Attributes: map[string]string{cliproxyauth.AttributePath: path},
		Metadata:   map[string]any{"type": "codex", "access_token": "working", "refresh_token": t.Name(), "expired": time.Now().Add(time.Hour).Format(time.RFC3339)},
	}
	disk := auth.Clone().Metadata
	// This token has never reached the helper, so its process cache cannot mask a missing disk check.
	codexauth.RecordRefreshOutcomeUnknown(disk, codexauth.NewRefreshOutcomeUnknownError(codexauth.ClientID, t.Name(), "response_read", io.ErrUnexpectedEOF))
	if errWrite := codexauth.WriteJSONFileAtomic(path, disk); errWrite != nil {
		t.Fatal(errWrite)
	}
	for _, ctx := range []context.Context{context.Background(), cliproxyauth.WithForceRefresh(context.Background())} {
		_, errRefresh := NewCodexExecutor(&config.Config{}).Refresh(ctx, auth.Clone())
		if !codexauth.IsRefreshOutcomeUnknown(errRefresh) || calls.Load() != 0 {
			t.Fatalf("persisted unresolved grant was replayed: err=%v calls=%d", errRefresh, calls.Load())
		}
	}
	disk["refresh_token"] = t.Name() + "-replacement"
	if errWrite := codexauth.WriteJSONFileAtomic(path, disk); errWrite != nil {
		t.Fatal(errWrite)
	}
	updated, errRefresh := NewCodexExecutor(&config.Config{}).Refresh(cliproxyauth.WithForceRefresh(context.Background()), auth.Clone())
	if errRefresh != nil || updated == nil || updated.Metadata["access_token"] != "recovered" || calls.Load() != 1 {
		t.Fatalf("replacement grant did not recover: err=%v calls=%d", errRefresh, calls.Load())
	}
}

func TestCodexRefreshPersistenceFailurePreservesUnknownOutcome(t *testing.T) {
	path := filepath.Join(t.TempDir(), "codex.json")
	auth := &cliproxyauth.Auth{ID: "codex.json", Provider: "codex", Attributes: map[string]string{cliproxyauth.AttributePath: path},
		Metadata: map[string]any{"access_token": "previous", "refresh_token": path, "expired": time.Now().Add(time.Hour).Format(time.RFC3339)},
	}
	if errWrite := codexauth.WriteJSONFileAtomic(path, auth.Metadata); errWrite != nil {
		t.Fatal(errWrite)
	}
	originalTransport := http.DefaultTransport
	http.DefaultTransport = codexOutcomeTransport(func(req *http.Request) (*http.Response, error) {
		// A concurrent uncooperative writer can invalidate the locked snapshot.
		if errWrite := os.WriteFile(path, []byte("invalid JSON"), 0o600); errWrite != nil {
			t.Fatal(errWrite)
		}
		return nil, errors.New("acceptance unknown")
	})
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	_, errRefresh := NewCodexExecutor(&config.Config{}).Refresh(cliproxyauth.WithForceRefresh(context.Background()), auth.Clone())
	if !codexauth.IsRefreshOutcomeUnknown(errRefresh) {
		t.Fatalf("persistence error hid unknown refresh outcome: %v", errRefresh)
	}
}

func TestCodexRefreshHomeOwnsOuterOutcomeReconciliation(t *testing.T) {
	cfg := &config.Config{}
	cfg.Home.Enabled = true
	auth := &cliproxyauth.Auth{ID: t.Name(), Provider: "codex", Metadata: map[string]any{
		"access_token": "stale-access", "refresh_token": t.Name(), "expired": time.Now().Add(-time.Hour).Format(time.RFC3339),
	}}
	codexauth.RecordRefreshOutcomeUnknown(auth.Metadata, codexauth.NewRefreshOutcomeUnknownError(codexauth.ClientID, t.Name(), "response_read", io.ErrUnexpectedEOF))
	_, errRefresh := NewCodexExecutor(cfg).Refresh(cliproxyauth.WithForceRefresh(context.Background()), auth)
	if errRefresh == nil || codexauth.IsRefreshOutcomeUnknown(errRefresh) || errRefresh.Error() != "home control center unavailable" {
		t.Fatalf("local outer fence bypassed Home's authoritative lookup: %v", errRefresh)
	}
}
