package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	log "github.com/sirupsen/logrus"
)

// codexRefreshAccessError keeps an unusable selected partition blocked even when
// another partition refreshed successfully. An unresolved grant alone does not
// invalidate an access token that is still usable.
func codexRefreshAccessError(auth *Auth, now time.Time) error {
	if auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") || auth.HasValidAccessToken(now) {
		return nil
	}
	return codex.RefreshOutcomeUnknown(auth.Metadata, IsCodexUseSIWC(auth))
}

// codexRefreshUnavailableForRequest keeps SIWC recovery from blocking a healthy
// outer token selected by a native Codex or image request. Other cooldowns and
// per-model failures remain owned by the normal selector checks.
func codexRefreshUnavailableForRequest(ctx context.Context, auth *Auth, now time.Time, headers ...http.Header) bool {
	if !auth.Unavailable || auth.LastError == nil || auth.LastError.Code != ErrorCodeRefreshOutcomeUnknown ||
		!strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") ||
		!IsCodexUseSIWC(auth) || IsCodexUseSIWCForRequest(ctx, auth, headers...) || auth.NextRetryAfter.After(now) ||
		codex.RefreshOutcomeUnknown(auth.Metadata, true) == nil {
		return auth.Unavailable
	}
	if authOuterAccessToken(auth) == "" {
		return true
	}
	expiry, hasExpiry := auth.OuterAccessTokenExpirationTime()
	return hasExpiry && !expiry.After(now)
}

// persistCodexRefreshOutcome merges safety state into the latest credential under
// its mutation gate. Unlike optional metadata, it must not be preempted by an
// unrelated credential edit or discarded because the other partition changed.
func (m *Manager) persistCodexRefreshOutcome(ctx context.Context, base *Auth, refreshErr error) error {
	ctx = WithoutSkipPersist(context.WithoutCancel(ctx))
	release, errLock := m.lockAuthMutationContext(ctx, base.ID)
	if errLock != nil {
		return errLock
	}
	defer release()

	m.mu.Lock()
	current := m.auths[base.ID]
	if current == nil || current.RegistrationEpoch != base.RegistrationEpoch || !strings.EqualFold(current.Provider, "codex") {
		m.mu.Unlock()
		return nil
	}
	before := current.Clone()
	updated := current.Clone()
	if updated.Metadata == nil {
		updated.Metadata = make(map[string]any)
	}
	if !codex.RecordRefreshOutcomeUnknown(updated.Metadata, refreshErr) {
		m.mu.Unlock()
		return nil
	}
	// Publish before releasing m.mu for I/O: later runtime snapshots must carry
	// the fence, and older queued saves must lose the persistence generation race.
	updated.Generation++
	m.auths[base.ID] = updated.Clone()
	errPersist := m.persistLocked(ctx, updated)
	current = m.auths[base.ID]
	if current != nil && current.RegistrationEpoch == base.RegistrationEpoch {
		mergeAuthSaveDelta(updated, before, current, false)
		codex.RecordRefreshOutcomeUnknown(updated.Metadata, refreshErr)
		if current.Generation > updated.Generation {
			updated.Generation = current.Generation
		}
		m.auths[base.ID] = updated.Clone()
	}
	m.mu.Unlock()
	if errPersist != nil {
		log.WithFields(log.Fields{"auth_id": base.ID, "provider": base.Provider}).Warnf("persist Codex refresh outcome failed: %v", errPersist)
		return fmt.Errorf("persist Codex refresh outcome: %w", errPersist)
	}
	return nil
}
