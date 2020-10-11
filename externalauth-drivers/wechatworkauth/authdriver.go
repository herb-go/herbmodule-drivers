package wechatworkauth

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	auth "github.com/herb-go/herbmodules/externalauth"
	"github.com/herb-go/deprecated/fetch"
	"github.com/herb-go/providers/tencent/wechatwork"
)

const FieldName = "externalauthdriver-wechatwork"
const StateLength = 128
const oauthURL = "https://open.weixin.qq.com/connect/oauth2/authorize"
const qrauthURL = "https://open.work.weixin.qq.com/wwopen/sso/qrConnect"

var DataIndexDepartment = auth.ProfileIndex("WechatWorkDartment")

type Session struct {
	State string
}

func mustHTMLRedirect(w http.ResponseWriter, url string) {
	w.WriteHeader(http.StatusOK)
	html := fmt.Sprintf(`<html><head><meta http-equiv="refresh" content="0; URL='%s'" /></head></html>`, url)
	_, err := w.Write([]byte(html))
	if err != nil {
		panic(err)
	}
}
func authRequestWithAgent(agent *wechatwork.Agent, provider *auth.Provider, r *http.Request) (*auth.Result, error) {
	var authsession = &Session{}
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
	info, err := agent.GetUserInfo(code)
	if fetch.CompareAPIErrCode(err, wechatwork.APIErrOauthCodeWrong) {
		return nil, auth.ErrAuthParamsError
	}
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, nil
	}
	result := auth.NewResult()
	result.Account = info.UserID
	result.Data.SetValue(auth.ProfileIndexAvatar, info.Avatar)
	result.Data.SetValue(auth.ProfileIndexEmail, info.Email)
	switch info.Gender {
	case wechatwork.APIResultGenderMale:
		result.Data.SetValue(auth.ProfileIndexGender, auth.ProfileGenderMale)
	case wechatwork.APIResultGenderFemale:
		result.Data.SetValue(auth.ProfileIndexGender, auth.ProfileGenderFemale)
	}
	result.Data.SetValue(auth.ProfileIndexName, info.Name)
	result.Data.SetValue(auth.ProfileIndexNickname, info.Name)
	for _, v := range info.Department {
		result.Data.AddValue(DataIndexDepartment, strconv.Itoa(v))
	}
	return result, nil
}

type OauthAuthDriver struct {
	agent *wechatwork.Agent
	scope string
}

type OauthAuthConfig struct {
	*wechatwork.Agent
	Scope string
}

func (c *OauthAuthConfig) Create() auth.Driver {
	return NewOauthDriver(c)
}
func NewOauthDriver(c *OauthAuthConfig) *OauthAuthDriver {
	return &OauthAuthDriver{
		agent: c.Agent,
		scope: c.Scope,
	}
}

func (d *OauthAuthDriver) ExternalLogin(provider *auth.Provider, w http.ResponseWriter, r *http.Request) {
	bytes, err := provider.Auth.RandToken(StateLength)
	if err != nil {
		panic(err)
	}
	state := string(bytes)
	authsession := Session{
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
	q.Set("appid", d.agent.CorpID)
	q.Set("agentid", strconv.Itoa(d.agent.AgentID))
	q.Set("scope", d.scope)
	q.Set("state", state)
	q.Set("redirect_uri", provider.AuthURL())
	u.RawQuery = q.Encode()
	u.Fragment = "wechat_redirect"
	mustHTMLRedirect(w, u.String())
}
func (d *OauthAuthDriver) AuthRequest(provider *auth.Provider, r *http.Request) (*auth.Result, error) {
	return authRequestWithAgent(d.agent, provider, r)
}

type QRAuthDriver struct {
	agent *wechatwork.Agent
}
type QRAuthConfig struct {
	*wechatwork.Agent
}

func (c *QRAuthConfig) Create() auth.Driver {
	return NewQRAuthDriver(c)
}

func NewQRAuthDriver(c *QRAuthConfig) *QRAuthDriver {
	return &QRAuthDriver{
		agent: c.Agent,
	}
}

func (d *QRAuthDriver) ExternalLogin(provider *auth.Provider, w http.ResponseWriter, r *http.Request) {
	bytes, err := provider.Auth.RandToken(StateLength)
	if err != nil {
		panic(err)
	}
	state := string(bytes)
	authsession := Session{
		State: state,
	}
	err = provider.Auth.Session.Set(r, FieldName, authsession)
	if err != nil {
		panic(err)
	}
	u, err := url.Parse(qrauthURL)
	if err != nil {
		panic(err)
	}
	q := u.Query()
	q.Set("appid", d.agent.CorpID)
	q.Set("agentid", strconv.Itoa(d.agent.AgentID))
	q.Set("state", state)
	q.Set("redirect_uri", provider.AuthURL())
	u.RawQuery = q.Encode()
	mustHTMLRedirect(w, u.String())
}
func (d *QRAuthDriver) AuthRequest(provider *auth.Provider, r *http.Request) (*auth.Result, error) {
	return authRequestWithAgent(d.agent, provider, r)
}
