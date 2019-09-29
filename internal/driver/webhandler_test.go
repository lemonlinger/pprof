package driver

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestWebHandler(t *testing.T) {
	h := NewWebHandler("/ui/")
	http.ListenAndServe(":12345", h)
}

func TestProfileName(t *testing.T) {
	fmt.Println(profileName("cpu", 10*time.Second, time.Now()))
}
