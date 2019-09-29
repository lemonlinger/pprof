package driver

import (
	"net/http"
	"testing"
)

func TestWebHandler(t *testing.T) {
	h := NewWebHandler()
	http.ListenAndServe(":12345", h)
}
