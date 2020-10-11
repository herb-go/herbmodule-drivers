package tomlappkey

import (
	"sync"

	"github.com/herb-go/uniqueid"

	"github.com/herb-go/herbsecurity/authority"
	"github.com/herb-go/herbsecurity/authority/service/application"
	"github.com/herb-go/providers/herb/statictoml"
)

type Applications struct {
	Source       statictoml.Source
	locker       sync.Mutex
	Data         map[string]*application.Verified
	KeyGenerator func() ([]byte, error)
	IDGenerator  func() (string, error)
}

func (apps *Applications) load() error {
	data := NewData(nil)
	err := apps.Source.Load(&data)
	if err != nil {
		return err
	}
	apps.Data = ConvertFromApps(data.Apps)
	return nil
}
func (apps *Applications) save() error {
	data := ConvertToApps(apps.Data)
	return apps.Source.Save(NewData(data))
}
func (apps *Applications) CreateApplication(p authority.Principal, a authority.Agent, payloads *authority.Payloads) (*application.Verified, error) {
	var err error
	if p == "" {
		return nil, authority.ErrEmptyPrincipal
	}
	apps.locker.Lock()
	defer apps.locker.Unlock()
	id, err := apps.IDGenerator()
	if err != nil {
		return nil, err
	}
	pass, err := apps.KeyGenerator()
	if err != nil {
		return nil, err
	}
	app := application.NewVerified()
	app.Principal = p
	app.Agent = a

	app.Authority = authority.Authority(id)
	app.Passphrase = authority.Passphrase(pass)
	app.Payloads = payloads
	apps.Data[string(app.Authority)] = app
	err = apps.save()
	if err != nil {
		return nil, err
	}
	return app, nil
}

func (apps *Applications) RegenerateApplication(p authority.Principal, a authority.Authority) error {
	apps.locker.Lock()
	defer apps.locker.Unlock()
	if a == "" {
		return authority.ErrEmptyAuthority
	}
	app := apps.Data[string(a)]
	if app == nil || app.Principal != p {
		return authority.ErrNotFound
	}
	pass, err := apps.KeyGenerator()
	if err != nil {
		return err
	}
	app.Passphrase = authority.Passphrase(pass)
	apps.Data[string(app.Authority)] = app
	return apps.save()
}

func (apps *Applications) RevokeApplication(p authority.Principal, a authority.Authority) error {
	apps.locker.Lock()
	defer apps.locker.Unlock()
	if a == "" {
		return authority.ErrEmptyAuthority
	}
	app := apps.Data[string(a)]
	if app == nil || app.Principal != p {
		return authority.ErrNotFound
	}
	delete(apps.Data, string(a))
	return apps.save()
}

func (apps *Applications) LoadApplication(a authority.Authority) (*application.Verified, error) {
	apps.locker.Lock()
	defer apps.locker.Unlock()
	if a == "" {
		return nil, nil
	}
	return apps.Data[string(a)], nil
}

func New() *Applications {
	return &Applications{
		Data:        map[string]*application.Verified{},
		IDGenerator: uniqueid.GenerateID,
	}
}
