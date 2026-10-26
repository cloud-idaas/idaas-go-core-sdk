package oauth2

import (
	stderrors "errors"
	"net/http"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	sdkerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
)

// TestParseOAuth2Error_Classification 覆盖 4xx/5xx × JSON/非 JSON 四种组合。
// 5xx 必须能被 errors.As(&*ServerError) 命中，4xx 必须不能。
func TestParseOAuth2Error_Classification(t *testing.T) {
	const oauthBody = `{"error":"temporarily_unavailable","error_description":"try later"}`
	const htmlBody = `<html><body>gateway</body></html>`

	cases := []struct {
		name       string
		status     int
		body       string
		wantServer bool
		wantOAuth  bool
		wantCode   string
	}{
		{"4xx json", http.StatusBadRequest, oauthBody, false, true, "temporarily_unavailable"},
		{"4xx non-json", http.StatusForbidden, htmlBody, false, false, constants.ClientError},
		{"5xx json", http.StatusServiceUnavailable, oauthBody, true, true, "temporarily_unavailable"},
		{"5xx non-json", http.StatusBadGateway, htmlBody, true, false, constants.ServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := parseOAuth2Error(&domain.HttpResponse{
				StatusCode: tc.status,
				Headers:    map[string][]string{},
				Body:       []byte(tc.body),
			})

			var serverErr *sdkerrors.ServerError
			if got := stderrors.As(err, &serverErr); got != tc.wantServer {
				t.Fatalf("errors.As(*ServerError) = %v, want %v (err=%T %v)", got, tc.wantServer, err, err)
			}
			if tc.wantServer && serverErr.StatusCode != tc.status {
				t.Errorf("ServerError.StatusCode = %d, want %d", serverErr.StatusCode, tc.status)
			}

			var oauthErr *sdkerrors.OAuth2Error
			if got := stderrors.As(err, &oauthErr); got != tc.wantOAuth {
				t.Errorf("errors.As(*OAuth2Error) = %v, want %v", got, tc.wantOAuth)
			}

			var coded interface{ ErrorCode() string }
			if !stderrors.As(err, &coded) || coded.ErrorCode() != tc.wantCode {
				t.Errorf("ErrorCode() = %v, want %q", coded, tc.wantCode)
			}
		})
	}
}
