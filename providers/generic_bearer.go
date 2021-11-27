package providers

import (
	"context"
	"net/http"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// GenericBearerProvider represents a generic Bearer header based Identity Provider
type GenericBearerProvider struct {
	*ProviderData
}

var _ Provider = (*GenericBearerProvider)(nil)

const (
	genericBearerProviderName = "Generic"
	genericBearerDefaultScope = "user:email"
)

var (
	// Default Login URL.
	genericBearerDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "localhost",
		Path:   "/login/oauth/authorize",
	}

	// Default Redeem URL.
	genericBearerDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "localhost",
		Path:   "/login/oauth/access_token",
	}

	// Default Validation URL.
	genericBearerDefaultValidateURL = &url.URL{
		Scheme: "https",
		Host:   "localhost",
		Path:   "/userinfo",
	}

	// Default Profile URL.
	genericBearerDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "localhost",
		Path:   "/userinfo",
	}
)

// NewGenericBearerProvider initiates a new GenericBearerProvider
func NewGenericBearerProvider(p *ProviderData) *GenericBearerProvider {
	p.setProviderDefaults(providerDefaults{
		name:        genericBearerProviderName,
		loginURL:    genericBearerDefaultLoginURL,
		redeemURL:   genericBearerDefaultRedeemURL,
		profileURL:  genericBearerDefaultProfileURL,
		validateURL: genericBearerDefaultValidateURL,
		scope:       genericBearerDefaultScope,
	})
	return &GenericBearerProvider{ProviderData: p}
}

func makeGenericBearerHeader(accessToken string) http.Header {
	return makeAuthorizationHeader(tokenTypeBearer, accessToken, map[string]string{})
}

// EnrichSession updates the User & Email after the initial Redeem
func (p *GenericBearerProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	var userInfo struct {
		Email    string `json:"email"`
		Username string `json:"username"`
	}

	endpoint := &url.URL{
		Scheme: p.ProfileURL.Scheme,
		Host:   p.ProfileURL.Host,
		Path:   p.ProfileURL.Path,
	}
	err := requests.New(endpoint.String()).
		WithContext(ctx).
		WithHeaders(makeGenericBearerHeader(s.AccessToken)).
		Do().
		UnmarshalInto(&userInfo)
	if err != nil {
		return err
	}

	s.Email = userInfo.Email
	s.User = userInfo.Username

	return nil
}

// ValidateSession validates the AccessToken
func (p *GenericBearerProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeGenericBearerHeader(s.AccessToken))
}