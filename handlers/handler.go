package handlers

import (
	"log"

	"github.com/mpdroog/radiusd/model"
)

type Handler struct {
	model.Storage
	*log.Logger
	Verbose bool
}
