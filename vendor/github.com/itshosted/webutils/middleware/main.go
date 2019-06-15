package middleware

/**
 * Middleware like Expressjs (NodeJS)
 *
 * Simply execute 'general code' before the MUX
 *  is applied.
 */
import (
	"net/http"
)

var (
	handlers []HandlerFunc
)

type HandlerFunc func(http.ResponseWriter, *http.Request) bool

func Add(handler HandlerFunc) {
	handlers = append(handlers, handler)
}

func Use(h *http.ServeMux) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, handler := range handlers {
			if !handler(w, r) {
				// Abort if function responded with false
				return
			}
		}

		h.ServeHTTP(w, r)
	}
}
