package wechatmpauth

import (
	"fmt"
	"net/http"
	"net/url"

	auth "github.com/herb-go/herbmodules/externalauth"
	"github.com/herb-go/fetcher"
	"github.com/herb-go/providers/tencent/wechatmp"
)

const FieldName = "externalauthdriver-wechatmp"
const StateLength = 128
const oauthURL = "https://open.weixin.qq.com/connect/oauth2/authorize"

const ProfileIndexOpenID = auth.ProfileIndex("OpenID")
const ProfileIndexUnionID = auth.ProfileIndex("UnionID")

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
func authRequest(driver *OauthAuthDriver, provider *auth.Provider, r *http.Request) (*auth.Result, error) {
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
	info, err := driver.app.GetUserInfo(code, driver.Scope, driver.Lang)
	if fetcher.CompareAPIErrCode(err, wechatmp.APIErrOauthCodeWrong) {
		return nil, auth.ErrAuthParamsError
	}
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, nil
	}
	result := auth.NewResult()
	if driver.IDField == "unionid" {
		if info.UnionID == "" {
			return nil, nil
		}
		result.Account = info.UnionID
	} else {
		result.Account = info.OpenID
	}
	if info.HeadimgURL != "" {
		result.Data.SetValue(auth.ProfileIndexAvatar, info.HeadimgURL)
	}

	switch info.Sex {
	case wechatmp.APIResultGenderMale:
		result.Data.SetValue(auth.ProfileIndexGender, auth.ProfileGenderMale)
	case wechatmp.APIResultGenderFemale:
		result.Data.SetValue(auth.ProfileIndexGender, auth.ProfileGenderFemale)
	}

	if info.Nickname != "" {
		result.Data.SetValue(auth.ProfileIndexNickname, info.Nickname)
	}
	if info.Country != "" {
		result.Data.SetValue(auth.ProfileIndexCountry, info.Country)
	}
	if info.Province != "" {
		result.Data.SetValue(auth.ProfileIndexProvince, info.Province)
	}
	if info.City != "" {
		result.Data.SetValue(auth.ProfileIndexCity, info.City)
	}
	if info.UnionID != "" {
		result.Data.SetValue(ProfileIndexUnionID, info.UnionID)
	}
	result.Data.SetValue(auth.ProfileIndexAccessToken, info.AccessToken)
	result.Data.SetValue(ProfileIndexOpenID, info.OpenID)
	return result, nil
}

type OauthAuthDriver struct {
	app     *wechatmp.App
	Scope   string
	Lang    string
	IDField string
}
type OauthAuthConfig struct {
	*wechatmp.App
	Scope   string
	Lang    string
	IDField string
}

func (c *OauthAuthConfig) Create() auth.Driver {
	return NewOauthDriver(c)
}
func NewOauthDriver(c *OauthAuthConfig) *OauthAuthDriver {
	return &OauthAuthDriver{
		app:     c.App,
		Scope:   c.Scope,
		Lang:    c.Lang,
		IDField: c.IDField,
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
	q.Set("response_type", "code")
	q.Set("appid", d.app.AppID)
	q.Set("scope", d.Scope)
	q.Set("state", state)
	q.Set("redirect_uri", provider.AuthURL())
	u.RawQuery = q.Encode()
	u.Fragment = "wechat_redirect"
	mustHTMLRedirect(w, u.String())
}
func (d *OauthAuthDriver) AuthRequest(provider *auth.Provider, r *http.Request) (*auth.Result, error) {
	return authRequest(d, provider, r)
}
