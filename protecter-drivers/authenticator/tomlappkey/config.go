package tomlappkey

import (
	"sync"

	"github.com/herb-go/herbmodules/protecter/authenticator/appsecretsign"

	"github.com/herb-go/herbmodules/protecter/authenticator"
	"github.com/herb-go/herbmodules/protecter/authenticator/appsecret"
	"github.com/herb-go/herbsecurity/authority/credential"
	"github.com/herb-go/misc/generator"
	"github.com/herb-go/providers/herb/statictoml"
)

var locker sync.Mutex
var registered = map[statictoml.Source]*Applications{}

func Flush() {
	locker.Lock()
	locker.Unlock()
	registered = map[statictoml.Source]*Applications{}
}

var DefaultKeycharList = generator.AlphanumericList
var DefaultMin = 32

type Config struct {
	Source      statictoml.Source
	Example     statictoml.Source
	KeycharList string
	KeyMin      int
	KeyMax      int
}

func (c *Config) Create() (*Applications, error) {
	locker.Lock()
	locker.Unlock()
	source, err := c.Source.Abs()
	if err != nil {
		return nil, err
	}
	err = source.VerifyWithExample(c.Example)
	if err != nil {
		return nil, err
	}
	apps, ok := registered[source]
	if ok && apps != nil {
		return apps, nil
	}
	apps = New()
	keygenerator := &generator.ListGenerator{}
	if c.KeycharList == "" {
		keygenerator.List = DefaultKeycharList
	} else {
		keygenerator.List = []byte(c.KeycharList)
	}
	if c.KeyMin == 0 {
		keygenerator.Min = DefaultMin
	} else {
		keygenerator.Min = c.KeyMin
	}
	keygenerator.Max = c.KeyMax
	apps.KeyGenerator = keygenerator.Generate
	apps.Source = source
	err = apps.load()
	if err != nil {
		return nil, err
	}
	return apps, nil
}
func CreateAuthenticator(loader func(interface{}) error) (credential.Authenticator, error) {
	c := &Config{}
	err := loader(c)
	if err != nil {
		return nil, err
	}
	apps, err := c.Create()
	if err != nil {
		return nil, err
	}
	a := appsecret.New()
	a.Loader = apps
	return a, nil
}

var AuthenticatorFactory authenticator.AuthenticatorFactory = authenticator.AuthenticatorFactoryFunc(CreateAuthenticator)

func NewConfig() *Config {
	return &Config{}
}

type SignerConfig struct {
	appsecretsign.SignerConfig
	Config
}

func CreateSignerAuthenticator(loader func(interface{}) error) (credential.Authenticator, error) {
	c := &SignerConfig{}
	err := loader(c)
	if err != nil {
		return nil, err
	}
	apps, err := c.Create()
	if err != nil {
		return nil, err
	}
	signer, err := c.SignerConfig.Load()
	if err != nil {
		return nil, err
	}
	a := appsecretsign.New()
	a.Loader = apps
	a.Signer = signer
	return a, nil
}

var SignerAuthenticatorFactory authenticator.AuthenticatorFactory = authenticator.AuthenticatorFactoryFunc(CreateSignerAuthenticator)
