package githubauth

import (
	"net/http"
	"net/url"
	"strconv"

	auth "github.com/herb-go/herbmodules/externalauth"
	"github.com/herb-go/deprecated/fetch"
	"github.com/herb-go/providers/github"
)

const StateLength = 128

var TokenMask = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")

const oauthURL = "https://github.com/login/oauth/authorize"

const FieldName = "externalauthdriver-github"

type StateSession struct {
	State string
}
type OauthAuthDriver struct {
	client *github.Client
	scope  string
}

type OauthAuthConfig struct {
	*github.Client
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
func (d *OauthAuthDriver) ExternalLogin(service *auth.Provider, w http.ResponseWriter, r *http.Request) {
	bytes, err := service.Auth.RandToken(StateLength)
	if err != nil {
		panic(err)
	}
	state := string(bytes)
	authsession := StateSession{
		State: state,
	}
	err = service.Auth.Session.Set(r, FieldName, authsession)
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
	q.Set("redirect_uri", service.AuthURL())
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
	result, err := d.client.GetAccessToken(code)
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
	authresult.Account = u.Login
	authresult.Data.SetValue(auth.ProfileIndexAccessToken, result.AccessToken)
	authresult.Data.SetValue(auth.ProfileIndexAvatar, u.AvatarURL)
	authresult.Data.SetValue(auth.ProfileIndexEmail, u.Email)
	authresult.Data.SetValue(auth.ProfileIndexName, u.Name)
	authresult.Data.SetValue(auth.ProfileIndexNickname, u.Login)
	authresult.Data.SetValue(auth.ProfileIndexProfileURL, u.HTMLURL)
	authresult.Data.SetValue(auth.ProfileIndexID, strconv.Itoa(u.ID))
	authresult.Data.SetValue(auth.ProfileIndexCompany, u.Company)
	authresult.Data.SetValue(auth.ProfileIndexLocation, u.Location)
	authresult.Data.SetValue(auth.ProfileIndexWebsite, u.Blog)
	return authresult, nil
}
