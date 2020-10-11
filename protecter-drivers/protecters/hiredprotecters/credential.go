package hiredprotecters

import (
	"net/http"

	"github.com/herb-go/herbsecurity/authority/credential"
)

type Credential struct {
	request      *http.Request
	credentialer *Credentialer
}

func (c *Credential) NameData() (credential.Name, error) {
	return c.credentialer.credentialName, nil
}
func (c *Credential) ValueData() (credential.Value, error) {
	data, _, err := c.credentialer.field.LoadInfo(c.request)
	return data, err
}
