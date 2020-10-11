package tomlappkey

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/herb-go/herbsecurity/authority"
	"github.com/herb-go/providers/herb/statictoml"
)

func TestConfig(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "")
	if tmpdir == "" || err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	source := path.Join(tmpdir, "test.static.toml")
	err = ioutil.WriteFile(source, []byte{}, 0700)
	if err != nil {
		panic(err)
	}
	c := NewConfig()
	c.Source = statictoml.Source(source)
	apps, err := c.Create()
	if err != nil {
		panic(err)
	}
	v, err := apps.LoadApplication("test")
	if err != nil {
		panic(err)
	}
	if v != nil {
		t.Fatal(v)
	}
	pl := authority.NewPayloads()
	pl.Set("testpayloadname", []byte("testpayloadvalue"))
	v, err = apps.CreateApplication("test", "agent", pl)
	if err != nil {
		panic(err)
	}
	if v == nil || v.Principal != "test" {
		t.Fatal(v)
	}
	apps, err = c.Create()
	if err != nil {
		panic(err)
	}
	v2, err := apps.LoadApplication(v.Authority)
	if err != nil {
		panic(err)
	}
	if v2 == nil || v2.Principal != "test" || v2.Passphrase != v.Passphrase || v2.Agent != "agent" || v2.Payloads.LoadString("testpayloadname") != "testpayloadvalue" {
		t.Fatal(v2)
	}
	err = apps.RegenerateApplication("test", v.Authority)
	if err != nil {
		panic(err)
	}
	v2, err = apps.LoadApplication(v.Authority)
	if err != nil {
		panic(err)
	}
	if v2 == nil || v2.Principal != "test" || v2.Passphrase == v.Passphrase || v2.Agent != "agent" || v2.Payloads.LoadString("testpayloadname") != "testpayloadvalue" {
		t.Fatal(v2)
	}
	err = apps.RevokeApplication(v.Principal, v.Authority)
	if err != nil {
		panic(err)
	}
	v2, err = apps.LoadApplication(v.Authority)
	if err != nil {
		panic(err)
	}
	if v2 != nil {
		t.Fatal(v2)
	}
}
