package codex

import "testing"

func TestOAuthTokenResponsePreservesDecoderFieldSemantics(t *testing.T) {
	response, errParse := parseOAuthTokenResponse([]byte(`{"access_token":"access","refresh_token":"old","refresh_token":"rotated","EXPIRES_IN":3600,"id_token":"id","id_token":null}`))
	if errParse != nil || response.RefreshToken != "rotated" || response.ExpiresIn != 3600 || response.IDToken != "id" {
		t.Fatalf("decoder discarded token fields: response=%#v err=%v", response, errParse)
	}
}
