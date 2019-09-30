package driver

import (
	"net/http"

	internaldriver "github.com/lemonlinger/pprof/internal/driver"
)

func Handler(prefix, path string) http.Handler {
	h := internaldriver.NewWebHandler(prefix, path)
	return h
}
