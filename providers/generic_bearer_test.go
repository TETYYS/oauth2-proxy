package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func testGenericBearerProvider(hostname string) *GenericBearerProvider {
	p := NewGenericBearerProvider(
		&ProviderData{
			ProviderName: "",
			Scope:        ""})
	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
	}
	return p
}

func testGenericBearerBackend(payloads map[string][]string) *httptest.Server {
	pathToQueryMap := map[string][]string{
		"/userinfo":    {""},
	}

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			query, ok := pathToQueryMap[r.URL.Path]
			validQuery := false
			index := 0
			for i, q := range query {
				if q == r.URL.RawQuery {
					validQuery = true
					index = i
				}
			}
			payload := []string{}
			if ok && validQuery {
				payload, ok = payloads[r.URL.Path]
			}
			if !ok {
				w.WriteHeader(404)
			} else if !validQuery {
				w.WriteHeader(404)
			} else if payload[index] == "" {
				w.WriteHeader(204)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload[index]))
			}
		}))
}

func TestNewGenericBearerProvider(t *testing.T) {
	g := NewWithT(t)

	// Test that defaults are set when calling for a new provider with nothing set
	providerData := NewGenericBearerProvider(&ProviderData{}).Data()
	g.Expect(providerData.ProviderName).To(Equal("Generic"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://localhost/login/oauth/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://localhost/login/oauth/access_token"))
	g.Expect(providerData.ProfileURL.String()).To(Equal("https://localhost/userinfo"))
	g.Expect(providerData.ValidateURL.String()).To(Equal("https://localhost/userinfo"))
	g.Expect(providerData.Scope).To(Equal("user:email"))
}

func TestGenericBearerProviderOverrides(t *testing.T) {
	p := NewGenericBearerProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/login/oauth/authorize"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/login/oauth/access_token"},
			ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "api.example.com",
				Path:   "/"},
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Generic", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/login/oauth/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/login/oauth/access_token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://api.example.com/",
		p.Data().ValidateURL.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestGenericBearerProvider_EnrichSession(t *testing.T) {
	b := testGenericBearerBackend(map[string][]string{
		"/userinfo": {`{"email": "example@email.com", "username": "example"}`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGenericBearerProvider(bURL.Host)

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NoError(t, err)
	assert.Equal(t, "example@email.com", session.Email)
	assert.Equal(t, "example", session.User)
}