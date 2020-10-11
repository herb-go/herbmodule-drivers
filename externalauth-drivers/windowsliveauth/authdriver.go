package windowsliveauth

import (
	"net/http"
	"net/url"

	auth "github.com/herb-go/herbmodules/externalauth"
	"github.com/herb-go/deprecated/fetch"
	"github.com/herb-go/providers/windowslive"
)

const StateLength = 128

const oauthURL = "https://login.live.com/oauth20_authorize.srf"

const FieldName = "externalauthdriver-windowslive"

type StateSession struct {
	State string
}
type OauthAuthDriver struct {
	client *windowslive.Client
	scope  string
}
type OauthAuthConfig struct {
	*windowslive.Client
	Scope string
}

func (c *OauthAuthConfig) Create() auth.Driver {
	return NewOauthDriver(c)
}
func NewOauthDriver(c *OauthAuthConfig) *OauthAuthDriver {
	return &OauthAuthDriver{
		client: c.Client,
		scope:  c.Scope,
	}
}
func (d *OauthAuthDriver) ExternalLogin(provider *auth.Provider, w http.ResponseWriter, r *http.Request) {
	bytes, err := provider.Auth.RandToken(StateLength)
	if err != nil {
		panic(err)
	}
	state := string(bytes)
	authsession := StateSession{
		State: state,
	}
	err = provider.Auth.Session.Set(r, FieldName, authsession)
	if err != nil {
		panic(err)
	}
	u, err := url.Parse(oauthURL)
	if err != nil {
		panic(err)
	}
	q := u.Query()
	q.Set("client_id", d.client.ClientID)
	q.Set("scope", d.scope)
	q.Set("state", state)
	q.Set("response_type", "code")
	q.Set("redirect_uri", provider.AuthURL())
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), 302)
}

func (d *OauthAuthDriver) AuthRequest(provider *auth.Provider, r *http.Request) (*auth.Result, error) {
	var authsession = &StateSession{}
	q := r.URL.Query()
	var code = q.Get("code")
	if code == "" {
		return nil, nil
	}
	var state = q.Get("state")
	if state == "" {
		return nil, auth.ErrAuthParamsError
	}
	err := provider.Auth.Session.Get(r, FieldName, authsession)
	if provider.Auth.Session.IsNotFoundError(err) {
		return nil, nil
	}
	if authsession.State == "" || authsession.State != state {
		return nil, auth.ErrAuthParamsError
	}
	err = provider.Auth.Session.Del(r, FieldName)
	if err != nil {
		return nil, err
	}
	result, err := d.client.GetAccessToken(code, provider.AuthURL())
	if err != nil {
		statuscode := fetch.GetErrorStatusCode(err)
		if statuscode > 400 && statuscode < 500 {
			return nil, auth.ErrAuthParamsError
		}
		return nil, err
	}
	if result.AccessToken == "" {
		return nil, auth.ErrAuthParamsError
	}
	u, err := d.client.GetUser(result.AccessToken)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, nil
	}
	authresult := auth.NewResult()
	authresult.Account = u.ID
	authresult.Data.SetValue(auth.ProfileIndexFirstName, u.FirstName)
	authresult.Data.SetValue(auth.ProfileIndexLastName, u.LastName)
	authresult.Data.SetValue(auth.ProfileIndexLocale, u.Locale)
	authresult.Data.SetValue(auth.ProfileIndexAccessToken, result.AccessToken)
	authresult.Data.SetValue(auth.ProfileIndexName, u.Name)
	return authresult, nil
}
