package codex

import (
	"io"
	"testing"
)

func TestRefreshOutcomeSurvivesStaleSavesAndPartialRefresh(t *testing.T) {
	disk := map[string]any{
		"refresh_token": "outer", "access_token": "working",
		"siwc": map[string]any{"refresh_token": "siwc", "access_token": "siwc-access", "client_id": "client"},
	}
	outcome := NewRefreshOutcomeUnknownError(ClientID, "outer", "response_read", io.ErrUnexpectedEOF)
	RecordRefreshOutcomeUnknown(disk, outcome)
	stale := map[string]any{"refresh_token": "outer", "access_token": "working"}
	for _, merged := range []map[string]any{MergeWithDiskMap(disk, stale), MergeCodexCredentialsFromDisk(disk, stale)} {
		if RefreshOutcomeUnknown(merged, false) == nil {
			t.Fatal("stale save erased the persisted fence")
		}
	}
	after := cloneStringAnyMap(disk)
	after["siwc"].(map[string]any)["refresh_token"] = "siwc-new"
	patch := NewCredentialRefreshPatch(disk, after, false, true)
	patch.SetPartitionErrors(outcome, nil)
	merged := patch.Apply(disk)
	if RefreshOutcomeUnknown(merged, false) == nil || merged["siwc"].(map[string]any)["refresh_token"] != "siwc-new" {
		t.Fatal("partial refresh lost the unresolved partition")
	}
	replacement := cloneStringAnyMap(disk)
	replacement["refresh_token"] = "outer-replacement"
	if RefreshOutcomeUnknown(patch.Apply(replacement), false) != nil {
		t.Fatal("stale partial refresh quarantined a replacement partition")
	}
}
