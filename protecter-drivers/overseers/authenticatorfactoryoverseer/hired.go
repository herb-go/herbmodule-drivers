package authenticatorfactoryoverseer

import (
	"github.com/herb-go/herbmodules/protecter/authenticator"
	"github.com/herb-go/worker"
)

var factoryworker authenticator.AuthenticatorFactory
var Team = worker.GetWorkerTeam(&factoryworker)

func GetAuthenticatorFactoryByID(id string) authenticator.AuthenticatorFactory {
	w := worker.FindWorker(id)
	if w == nil {
		return nil
	}
	c, ok := w.Interface.(*authenticator.AuthenticatorFactory)
	if ok == false || c == nil {
		return nil
	}
	return *c
}
