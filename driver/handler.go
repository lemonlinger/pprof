package driver

import (
	"net/http"

	internaldriver "github.com/lemonlinger/pprof/internal/driver"
)

func Handler(path string) http.Handler {
	h := internaldriver.NewWebHandler(path)
	return h
}
