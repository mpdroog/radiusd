package handlers

import (
	"log"
	"time"

	"github.com/mpdroog/radiusd/model"
)

// Keep state for EAP-Messages
type State struct {
	RemoteID uint8     // Last received ID from remote
	LastID   uint8     // Last used ID
	Token    uint32    // Random token for pass
	Added    time.Time // Time added to state-map
}

type Handler struct {
	model.Storage
	*log.Logger
	Verbose bool

	State map[string]State
}
