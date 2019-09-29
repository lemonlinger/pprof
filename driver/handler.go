package driver

import "net/http"

func Handler() http.Handler {
	h := internaldriver.NewWebHandler()
	return h
}
