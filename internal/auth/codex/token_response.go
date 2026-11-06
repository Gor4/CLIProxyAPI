package codex

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/MoeForge/moego/ojson"
)

type oauthTokenResponse struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	Scope        string
	ExpiresIn    int
}

func parseOAuthTokenResponse(body []byte) (oauthTokenResponse, error) {
	var response oauthTokenResponse
	if !ojson.ValidBytes(body) {
		return response, fmt.Errorf("invalid OAuth token response JSON")
	}
	root := ojson.ParseBytes(body)
	if !root.IsObject() {
		return response, fmt.Errorf("OAuth token response must be an object")
	}
	var errDecode error
	// Preserve the previous decoder's case-insensitive names and last-value
	// handling, especially when a later refresh_token contains the rotated grant.
	root.ForEach(func(key, value ojson.Result) bool {
		if value.Type == ojson.Null {
			return true
		}
		var target *string
		name := strings.ToLower(key.String())
		switch name {
		case "access_token":
			target = &response.AccessToken
		case "refresh_token":
			target = &response.RefreshToken
		case "id_token":
			target = &response.IDToken
		case "token_type":
			target = &response.TokenType
		case "scope":
			target = &response.Scope
		case "expires_in":
			if value.Type != ojson.Number {
				errDecode = fmt.Errorf("OAuth token response has invalid expires_in type")
				return false
			}
			seconds, errParse := strconv.Atoi(value.Raw)
			if errParse != nil {
				errDecode = fmt.Errorf("OAuth token response has invalid expires_in")
				return false
			}
			response.ExpiresIn = seconds
			return true
		default:
			return true
		}
		if value.Type != ojson.String {
			errDecode = fmt.Errorf("OAuth token response has invalid %s type", name)
			return false
		}
		*target = value.String()
		return true
	})
	return response, errDecode
}
