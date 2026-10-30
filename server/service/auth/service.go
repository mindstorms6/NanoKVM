package auth

import (
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Service struct {
	mutex          sync.Mutex
	flows          map[string]oidcFlow
	flowStarts     map[string]oidcStartWindow
	provider       *oidc.Provider
	providerIssuer string
}

func NewService() *Service {
	return &Service{flows: make(map[string]oidcFlow), flowStarts: make(map[string]oidcStartWindow)}
}
