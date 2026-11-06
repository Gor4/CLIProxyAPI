package auth

import (
	"errors"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"net/http"
	"testing"
)

func TestUnknownRefreshOutcomeDiagnosticDoesNotPromiseRetry(t *testing.T) {
	errOutcome := codex.NewRefreshOutcomeUnknownError(codex.ClientID, "outer", "response_read", errors.New("lost response"))
	diagnostic := sanitizeRenewalError(&Auth{Provider: "codex"}, errOutcome)
	if diagnostic.Retryable || diagnostic.HTTPStatus == 0 {
		t.Fatalf("unknown grant advertised automatic recovery: %#v", diagnostic)
	}
}

func TestUnknownRefreshOutcomeDoesNotInheritCauseRejection(t *testing.T) {
	refusal := &Error{Code: "invalid_grant", Message: "401 unauthorized", HTTPStatus: http.StatusUnauthorized}
	outcome := codex.NewRefreshOutcomeUnknownError(codex.ClientID, t.Name(), "transport", refusal)
	nested := codex.NewRefreshOutcomeUnknownError(codex.ClientID, t.Name(), "transport", codex.NewPartitionRefreshError(refusal, errors.New("other partition diagnostic")))
	auth := &Auth{Provider: "codex"}
	for _, errRefresh := range []error{outcome, nested, codex.WrapSIWCRefreshError(nested), errors.Join(outcome, errors.New("persist failed"))} {
		if isTerminalRefreshError(auth, errRefresh) || isUnauthorizedError(errRefresh) {
			t.Fatal("an uncertain exchange inherited rejection from its transport cause")
		}
		diagnostic := sanitizeRenewalError(auth, errRefresh)
		if diagnostic.Code != ErrorCodeRefreshOutcomeUnknown || diagnostic.Retryable || diagnostic.HTTPStatus != http.StatusServiceUnavailable {
			t.Fatalf("uncertain outcome lost its recovery classification: %#v", diagnostic)
		}
	}
	combined := codex.NewPartitionRefreshError(outcome, refusal)
	if !isTerminalRefreshError(auth, combined) || sanitizeRenewalError(auth, combined).Code != "invalid_grant" {
		t.Fatal("uncertain outer exchange hid an explicit rejection of the other partition")
	}
	if !isTerminalRefreshError(auth, errors.Join(outcome, refusal)) {
		t.Fatal("an uncertain exchange hid an independently reported rejection")
	}
}
