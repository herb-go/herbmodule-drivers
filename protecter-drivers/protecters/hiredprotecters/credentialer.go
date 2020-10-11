package hiredprotecters

import (
	"net/http"

	"github.com/herb-go/herb/middleware/httpinfo"
	"github.com/herb-go/herbsecurity/authority/credential"
)

type Credentialer struct {
	credentialName credential.Name
	field          httpinfo.Field
}

func (c *Credentialer) CredentialRequest(r *http.Request) credential.CredentialSource {
	return &Credential{
		request:      r,
		credentialer: c,
	}
}
