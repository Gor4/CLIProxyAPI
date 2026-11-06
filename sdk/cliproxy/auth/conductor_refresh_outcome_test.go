package auth

import (
	"context"
	"errors"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"testing"
	"time"
)

func TestUnknownRefreshOutcomePreservesActiveAccessAndPersistsAfterCancellation(t *testing.T) {
	store := newMemoryAuthTestStore()
	manager := NewManager(store, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	token := t.Name()
	executor := &unauthorizedRefreshExecutor{
		id: "codex", onRefresh: cancel,
		refreshErr: codex.NewRefreshOutcomeUnknownError(codex.ClientID, token, "transport", context.Canceled),
	}
	manager.RegisterExecutor(executor)
	auth := &Auth{ID: t.Name(), Provider: "codex", Status: StatusActive, Metadata: map[string]any{
		"access_token": "working", "refresh_token": token, "expired": time.Now().Add(time.Hour).Format(time.RFC3339),
	}}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	if _, errRefresh := manager.ForceRefreshAuth(ctx, auth.ID); !codex.IsRefreshOutcomeUnknown(errRefresh) {
		t.Fatalf("refresh error = %v, want unknown outcome", errRefresh)
	}
	current, _ := manager.GetByID(auth.ID)
	if current.Unavailable || current.RequiresSignIn || current.RejectedRefreshToken != "" || authAccessToken(current) != "working" {
		t.Fatalf("unknown outcome invalidated a working credential: %#v", current)
	}
	stored, errList := store.List(context.Background())
	if errList != nil || len(stored) != 1 || codex.RefreshOutcomeUnknown(stored[0].Metadata, false) == nil {
		t.Fatalf("unknown outcome was not persisted: err=%v records=%d", errList, len(stored))
	}
}

func TestUnknownRefreshOutcomeDoesNotQuarantineConcurrentReplacement(t *testing.T) {
	store := newMemoryAuthTestStore()
	manager := NewManager(store, nil, nil)
	auth := &Auth{ID: t.Name(), Provider: "codex", Status: StatusActive, Metadata: map[string]any{
		"access_token": "old-access", "refresh_token": "old-refresh", "expired": time.Now().Add(time.Hour).Format(time.RFC3339),
	}}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	manager.RegisterExecutor(&unauthorizedRefreshExecutor{
		id: "codex", refreshErr: codex.NewRefreshOutcomeUnknownError(codex.ClientID, "old-refresh", "transport", errors.New("lost response")),
		onRefresh: func() {
			replacement, _ := manager.GetByID(auth.ID)
			replacement.Metadata["refresh_token"] = "replacement"
			replacement.Metadata["access_token"] = "replacement-access"
			if _, errUpdate := manager.Update(context.Background(), replacement); errUpdate != nil {
				t.Fatal(errUpdate)
			}
		},
	})
	manager.ForceRefreshAuth(context.Background(), auth.ID)
	current, _ := manager.GetByID(auth.ID)
	if current.Metadata["refresh_token"] != "replacement" || codex.RefreshOutcomeUnknown(current.Metadata, false) != nil || current.Unavailable {
		t.Fatal("stale unknown outcome changed replacement credentials")
	}
}

func TestUnknownRefreshOutcomeDoesNotRestoreRejectedAccessToken(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	auth := &Auth{ID: t.Name(), Provider: "codex", Status: StatusActive, Metadata: map[string]any{
		"access_token": "rejected-access", "refresh_token": t.Name(), "expired": time.Now().Add(time.Hour).Format(time.RFC3339),
	}}
	manager.RegisterExecutor(&unauthorizedRefreshExecutor{
		id: "codex", refreshErr: codex.NewRefreshOutcomeUnknownError(codex.ClientID, t.Name(), "response_read", errors.New("lost response")),
	})
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	manager.refreshAuthForRequest(context.Background(), auth.ID, "rejected-access")
	current, _ := manager.GetByID(auth.ID)
	if !current.Unavailable || current.RequiresSignIn || current.RejectedRefreshToken != "" {
		t.Fatal("unknown refresh restored rejected access or mislabeled the refresh token")
	}
}

func TestUnknownRefreshOutcomePersistsAcrossOtherPartitionReplacement(t *testing.T) {
	store := newMemoryAuthTestStore()
	manager := NewManager(store, nil, nil)
	auth := &Auth{ID: t.Name(), Provider: "codex", Status: StatusActive, Metadata: map[string]any{
		"access_token": "working", "refresh_token": "outer", "expired": time.Now().Add(time.Hour).Format(time.RFC3339),
		"siwc": map[string]any{"access_token": "siwc-old", "refresh_token": "siwc-old-refresh", "client_id": "client"},
	}}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	manager.RegisterExecutor(&unauthorizedRefreshExecutor{
		id: "codex", refreshErr: codex.NewRefreshOutcomeUnknownError(codex.ClientID, "outer", "transport", errors.New("lost response")),
		onRefresh: func() {
			current, _ := manager.GetByID(auth.ID)
			current.Metadata["siwc"].(map[string]any)["refresh_token"] = "siwc-replacement"
			if _, errUpdate := manager.Update(context.Background(), current); errUpdate != nil {
				t.Fatal(errUpdate)
			}
		},
	})
	manager.ForceRefreshAuth(context.Background(), auth.ID)
	stored, errList := store.List(context.Background())
	if errList != nil || len(stored) != 1 || codex.RefreshOutcomeUnknown(stored[0].Metadata, false) == nil {
		t.Fatal("unrelated SIWC replacement dropped the unresolved outer grant")
	}
	current, _ := manager.GetByID(auth.ID)
	if current.Metadata["siwc"].(map[string]any)["refresh_token"] != "siwc-replacement" || current.Unavailable {
		t.Fatal("recording the unresolved grant changed the replacement or working access token")
	}
}

func TestUnknownRefreshOutcomeRetriesFailedPersistence(t *testing.T) {
	store := newMemoryAuthTestStore()
	failSave := false
	manager := NewManager(&callbackAuthStore{save: func(auth *Auth) error {
		if failSave {
			return errors.New("synthetic disk full")
		}
		_, errSave := store.Save(context.Background(), auth)
		return errSave
	}}, nil, nil)
	auth := &Auth{ID: t.Name(), Provider: "codex", Status: StatusActive, Metadata: map[string]any{
		"access_token": "working", "refresh_token": t.Name(), "expired": time.Now().Add(time.Hour).Format(time.RFC3339),
	}}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	manager.RegisterExecutor(&unauthorizedRefreshExecutor{
		id: "codex", refreshErr: codex.NewRefreshOutcomeUnknownError(codex.ClientID, t.Name(), "transport", errors.New("lost response")),
	})
	failSave = true
	manager.ForceRefreshAuth(context.Background(), auth.ID)
	failSave = false
	manager.ForceRefreshAuth(context.Background(), auth.ID)
	stored, errList := store.List(context.Background())
	if errList != nil || len(stored) != 1 || codex.RefreshOutcomeUnknown(stored[0].Metadata, false) == nil {
		t.Fatal("retry skipped persistence after retaining the marker in memory")
	}
}

func TestUnknownRefreshOutcomePublishedBeforeStoreSnapshot(t *testing.T) {
	var manager *Manager
	store := &callbackAuthStore{save: func(auth *Auth) error {
		if codex.RefreshOutcomeUnknown(auth.Metadata, false) != nil {
			current, _ := manager.GetByID(auth.ID)
			if current == nil || codex.RefreshOutcomeUnknown(current.Metadata, false) == nil || current.Generation < auth.Generation {
				t.Error("concurrent runtime snapshots could omit the fence while its save is in progress")
			}
		}
		return nil
	}}
	manager = NewManager(store, nil, nil)
	auth := &Auth{ID: t.Name(), Provider: "codex", Status: StatusActive, Metadata: map[string]any{
		"access_token": "working", "refresh_token": t.Name(), "expired": time.Now().Add(time.Hour).Format(time.RFC3339),
	}}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	manager.RegisterExecutor(&unauthorizedRefreshExecutor{
		id: "codex", refreshErr: codex.NewRefreshOutcomeUnknownError(codex.ClientID, t.Name(), "transport", errors.New("lost response")),
	})
	manager.ForceRefreshAuth(context.Background(), auth.ID)
}

func TestUnknownRefreshOutcomeSurvivesQueuedOlderSave(t *testing.T) {
	store := newMemoryAuthTestStore()
	manager := NewManager(store, nil, nil)
	auth := &Auth{ID: t.Name(), Provider: "codex", Status: StatusActive, Metadata: map[string]any{
		"access_token": "working", "refresh_token": t.Name(), "expired": time.Now().Add(time.Hour).Format(time.RFC3339),
	}}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	stale, _ := manager.GetByID(auth.ID)
	manager.RegisterExecutor(&unauthorizedRefreshExecutor{
		id: "codex", refreshErr: codex.NewRefreshOutcomeUnknownError(codex.ClientID, t.Name(), "transport", errors.New("lost response")),
	})
	manager.ForceRefreshAuth(context.Background(), auth.ID)
	if errPersist := manager.persist(context.Background(), stale); errPersist != nil {
		t.Fatal(errPersist)
	}
	stored, errList := store.List(context.Background())
	if errList != nil || len(stored) != 1 || codex.RefreshOutcomeUnknown(stored[0].Metadata, false) == nil {
		t.Fatal("queued runtime snapshot erased the persisted outcome")
	}
}

func TestUnknownRefreshOutcomePreservesConcurrentRuntimeGeneration(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	manager := NewManager(&callbackAuthStore{save: func(auth *Auth) error {
		if codex.RefreshOutcomeUnknown(auth.Metadata, false) != nil {
			close(entered)
			<-release
		}
		return nil
	}}, nil, nil)
	auth := &Auth{ID: t.Name(), Provider: "codex", Status: StatusActive, Metadata: map[string]any{
		"access_token": "working", "refresh_token": t.Name(), "expired": time.Now().Add(time.Hour).Format(time.RFC3339),
	}}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	manager.RegisterExecutor(&unauthorizedRefreshExecutor{
		id: "codex", refreshErr: codex.NewRefreshOutcomeUnknownError(codex.ClientID, t.Name(), "transport", errors.New("lost response")),
	})
	done := make(chan error, 1)
	go func() {
		_, errRefresh := manager.ForceRefreshAuth(context.Background(), auth.ID)
		done <- errRefresh
	}()
	select {
	case <-entered:
	case errRefresh := <-done:
		t.Fatalf("refresh returned before its outcome save: %v", errRefresh)
	}
	manager.mu.Lock()
	manager.auths[auth.ID].Generation += 10
	expectedGeneration := manager.auths[auth.ID].Generation
	manager.mu.Unlock()
	close(release)
	if errRefresh := <-done; !codex.IsRefreshOutcomeUnknown(errRefresh) {
		t.Fatal(errRefresh)
	}
	current, _ := manager.GetByID(auth.ID)
	if current.Generation < expectedGeneration {
		t.Fatalf("runtime generation rolled back: got %d, want >= %d", current.Generation, expectedGeneration)
	}
}
