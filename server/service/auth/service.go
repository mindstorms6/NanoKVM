package auth

import (
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Service struct {
	mutex          sync.Mutex
	flows          map[string]oidcFlow
	provider       *oidc.Provider
	providerIssuer string
}

func NewService() *Service {
	return &Service{flows: make(map[string]oidcFlow)}
}
