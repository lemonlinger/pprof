package driver

import (
	"net/http"

	internaldriver "github.com/lemonlinger/pprof/internal/driver"
)

func Handler() http.Handler {
	h := internaldriver.NewWebHandler()
	return h
}
