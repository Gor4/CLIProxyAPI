package auth

import (
	"context"
	"fmt"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	log "github.com/sirupsen/logrus"
	"strings"
)

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
