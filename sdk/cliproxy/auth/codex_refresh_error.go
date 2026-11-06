package auth

import (
	"errors"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
)

// knownRefreshErrors keeps transport diagnostics of uncertain exchanges from
// becoming grant rejections. Preserve partition envelopes so explicit failures
// of another partition still retain their classification.
func knownRefreshErrors(err error) error {
	if !codex.IsRefreshOutcomeUnknown(err) {
		return err
	}
	if _, uncertain := err.(*codex.RefreshOutcomeUnknownError); uncertain {
		return nil
	}
	if _, partitioned := err.(interface {
		OuterRefreshError() error
		SIWCRefreshError() error
	}); partitioned {
		return err
	}
	if multi, ok := err.(interface{ Unwrap() []error }); ok {
		var known []error
		for _, nested := range multi.Unwrap() {
			known = append(known, knownRefreshErrors(nested))
		}
		return errors.Join(known...)
	}
	return knownRefreshErrors(errors.Unwrap(err))
}
