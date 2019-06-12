package qsnu

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

var (
	AuthURL    = "https://sso.qs.nu/oauth2/authorize"
	TokenURL   = "https://sso.qs.nu/oauth2/token"
	ProfileURL = "https://sso.qs.nu/api/v1/user"
)

type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	authURL      string
	tokenURL     string
	profileURL   string
}

func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "qsnu",
		profileURL:   ProfileURL,
	}
	p.config = newConfig(p, AuthURL, TokenURL, scopes)
	return p
}

func (p *Provider) Name() string {
	return p.providerName
}

func (p *Provider) SetName(name string) {
	p.providerName = name
}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

func (p *Provider) Debug(debug bool) {}

func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

func newConfig(provider *Provider, authURL, tokenURL string, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	}

	return c
}

func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}

	if user.AccessToken == "" {
		return user, fmt.Errorf("%s cannot get user info without accessToken", p.providerName)
	}

	resp, err := p.Client().Get(p.profileURL + "?access_token=" + url.QueryEscape(sess.AccessToken))
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return user, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user info", p.providerName, resp.StatusCode)
	}

	bits, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return user, err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)

	return user, err
}

func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		Name      string `json:"name"`
		Email     string `json:"email"`
		NickName  string `json:"username"`
		ID        string `json:"id"`
		AvatarURL string `json:"avatar_url"`
	}{}
	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}

	user.Email = u.Email
	user.Name = u.Name
	user.NickName = u.NickName
	user.UserID = u.ID
	user.AvatarURL = u.AvatarURL
	return nil
}
