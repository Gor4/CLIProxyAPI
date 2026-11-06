package auth

import (
	"context"
	"errors"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"net/http"
	"testing"
	"time"
)

type unknownPartialRefreshExecutor struct {
	unauthorizedRefreshExecutor
	refresh func(*Auth) (*Auth, error)
}

func (e *unknownPartialRefreshExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	return e.refresh(auth)
}

func TestPartialRefreshRetainsUnknownOutcomeDiagnostics(t *testing.T) {
	base := &Auth{Provider: "codex", Metadata: map[string]any{
		"refresh_token": "outer", "siwc": map[string]any{"refresh_token": "siwc", "client_id": "client"},
	}}
	updated := base.Clone()
	updated.Metadata["siwc"].(map[string]any)["refresh_token"] = "new-siwc"
	updated.CodexRefreshPatch = codex.NewCredentialRefreshPatch(base.Metadata, updated.Metadata, false, true)
	errOutcome := codex.NewRefreshOutcomeUnknownError(codex.ClientID, "outer", "response_read", errors.New("lost response"))
	updated.CodexRefreshPatch.SetPartitionErrors(errOutcome, nil)
	codex.RecordRefreshOutcomeUnknown(updated.Metadata, errOutcome)
	applyPreservedRenewalState(base, updated, updateModeRefresh, time.Now())
	if updated.RefreshError == nil || updated.RequiresSignIn || updated.RenewalVerified || updated.RejectedRefreshToken != "" {
		t.Fatal("partial success hid uncertainty or mislabeled the unresolved grant")
	}
}

func TestUnknownPartialRefreshDoesNotRestoreExpiredSelectedPartition(t *testing.T) {
	for _, useSIWC := range []bool{false, true} {
		name := "outer"
		if useSIWC {
			name = "siwc"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Now()
			auth := &Auth{ID: t.Name(), Provider: "codex", Status: StatusError, Unavailable: true,
				Metadata: map[string]any{
					"access_token": "outer-old", "refresh_token": "outer-refresh", "expired": now.Add(-time.Hour).Format(time.RFC3339),
					"use_siwc": useSIWC, "siwc": map[string]any{
						"access_token": "siwc-old", "refresh_token": "siwc-refresh", "client_id": "client", "expired": now.Add(-time.Hour).Format(time.RFC3339),
					},
				},
			}
			manager := NewManager(nil, nil, nil)
			manager.RegisterExecutor(&unknownPartialRefreshExecutor{
				unauthorizedRefreshExecutor: unauthorizedRefreshExecutor{id: "codex"},
				refresh: func(before *Auth) (*Auth, error) {
					updated := before.Clone()
					var outerErr, siwcErr error
					if useSIWC {
						updated.Metadata["access_token"] = "outer-new"
						updated.Metadata["expired"] = now.Add(time.Hour).Format(time.RFC3339)
						siwcErr = codex.NewRefreshOutcomeUnknownError("client", "siwc-refresh", "transport", errors.New("lost response"))
					} else {
						siwc := updated.Metadata["siwc"].(map[string]any)
						siwc["access_token"] = "siwc-new"
						siwc["expired"] = now.Add(time.Hour).Format(time.RFC3339)
						outerErr = codex.NewRefreshOutcomeUnknownError(codex.ClientID, "outer-refresh", "transport", errors.New("lost response"))
					}
					updated.CodexRefreshPatch = codex.NewCredentialRefreshPatch(before.Metadata, updated.Metadata, useSIWC, !useSIWC)
					updated.CodexRefreshPatch.SetPartitionErrors(outerErr, siwcErr)
					codex.RecordRefreshOutcomeUnknown(updated.Metadata, errors.Join(outerErr, siwcErr))
					return updated, nil
				},
			})
			if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
				t.Fatal(errRegister)
			}
			if _, errRefresh := manager.ForceRefreshAuth(context.Background(), auth.ID); errRefresh != nil {
				t.Fatal(errRefresh)
			}
			current, _ := manager.GetByID(auth.ID)
			if !current.Unavailable || current.Status != StatusError || current.RequiresSignIn {
				t.Fatalf("unresolved expired %s partition incorrectly restored: unavailable=%v status=%s sign_in=%v", name, current.Unavailable, current.Status, current.RequiresSignIn)
			}
			if useSIWC {
				headers := http.Header{"User-Agent": {"codex_cli_rs/1.0.0"}}
				blocked, _, _ := isAuthBlockedForModelForRequest(context.Background(), current, "model", now, headers)
				if blocked {
					t.Fatal("unresolved SIWC grant blocked the healthy outer token for a Codex client")
				}
			}
		})
	}
}

func TestUnknownSIWCOutcomePreservesRequestSpecificSelectionGuards(t *testing.T) {
	now := time.Now()
	base := &Auth{Provider: "codex", Status: StatusError, Unavailable: true,
		LastError: &Error{Code: ErrorCodeRefreshOutcomeUnknown, HTTPStatus: http.StatusServiceUnavailable},
		Metadata: map[string]any{
			"access_token": "outer", "refresh_token": "outer-refresh", "expired": now.Add(time.Hour).Format(time.RFC3339), "use_siwc": true,
			"siwc": map[string]any{"access_token": "siwc", "refresh_token": "siwc-refresh", "client_id": "client", "expires_at": now.Add(-time.Hour).Format(time.RFC3339)},
		},
	}
	codex.RecordRefreshOutcomeUnknown(base.Metadata, codex.NewRefreshOutcomeUnknownError("client", "siwc-refresh", "transport", errors.New("lost response")))
	for _, tc := range []struct {
		name    string
		native  bool
		mutate  func(*Auth)
		blocked bool
	}{
		{name: "healthy outer", native: true},
		{name: "expired SIWC", blocked: true},
		{name: "disabled", native: true, blocked: true, mutate: func(auth *Auth) { auth.Disabled = true }},
		{name: "rejected outer", native: true, blocked: true, mutate: func(auth *Auth) { auth.RejectedAccessToken = "outer" }},
		{name: "other cooldown", native: true, blocked: true, mutate: func(auth *Auth) { auth.NextRetryAfter = now.Add(time.Hour) }},
		{name: "credential quota", native: true, blocked: true, mutate: func(auth *Auth) {
			auth.Quota = QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: now.Add(time.Hour)}
		}},
		{name: "model cooldown", native: true, blocked: true, mutate: func(auth *Auth) {
			auth.ModelStates = map[string]*ModelState{"model": {Status: StatusError, Unavailable: true, NextRetryAfter: now.Add(time.Hour)}}
		}},
		{name: "unrelated error", native: true, blocked: true, mutate: func(auth *Auth) { auth.LastError.Code = "unrelated" }},
		{name: "other provider", native: true, blocked: true, mutate: func(auth *Auth) { auth.Provider = "claude" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := base.Clone()
			if tc.mutate != nil {
				tc.mutate(auth)
			}
			var headers http.Header
			if tc.native {
				headers = http.Header{"User-Agent": {"codex_cli_rs/1.0.0"}}
			}
			blocked, _, _ := isAuthBlockedForModelForRequest(context.Background(), auth, "model", now, headers)
			if blocked != tc.blocked {
				t.Fatalf("blocked = %v, want %v", blocked, tc.blocked)
			}
		})
	}
}
