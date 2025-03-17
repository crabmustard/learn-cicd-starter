package auth

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", bytes.NewBufferString(""))

	testValue := "11122224333"
	req.Header.Add("Authorization", "ApiKey "+testValue)

	recorder, _ := GetAPIKey(req.Header)

	if recorder != testValue {
		t.Errorf("Expected %s, got %s", testValue, recorder)
	}

}

func TestGetAPIKeyNoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", bytes.NewBufferString(""))

	_, err := GetAPIKey(req.Header)

	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Errorf("Expected %s, got %s", ErrNoAuthHeaderIncluded, err)
	}

}

func TestGetAPIKeyBadAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", bytes.NewBufferString(""))

	testValue := "11122224333"
	req.Header.Add("Authorization", "bad bad "+testValue)

	_, err := GetAPIKey(req.Header)

	if err.Error() != "malformed authorization header" {
		t.Errorf("Expected malformed authorization header, got %s", err.Error())
	}

}
