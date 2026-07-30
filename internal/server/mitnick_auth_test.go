package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/koodoxz/tameng/internal/config"
	"github.com/koodoxz/tameng/internal/logger"
)

func newMitnickTestServer(user, pass string) *Server {
	return &Server{
		log: logger.New("test"),
		cfg: &config.Config{
			Security: config.SecurityConfig{
				MitnickUser: user,
				MitnickPass: pass,
			},
		},
	}
}

func basicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestMitnickAuthMiddleware_RejectsMissingHeader(t *testing.T) {
	s := newMitnickTestServer("configuser", "configpass")
	handler := s.mitnickAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/mitnick/status", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestMitnickAuthMiddleware_RejectsCredentialsNotMatchingConfig(t *testing.T) {
	// Auth must be driven entirely by config -- any credentials other than
	// the ones in cfg.Security.Mitnick{User,Pass} must be rejected, proving
	// there is no fallback to a hardcoded value anywhere in the path.
	s := newMitnickTestServer("configuser", "configpass")
	handler := s.mitnickAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called with non-matching credentials")
	}))

	req := httptest.NewRequest(http.MethodGet, "/mitnick/status", nil)
	req.Header.Set("Authorization", basicAuthHeader("wronguser", "wrongpass"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for non-matching credentials, got %d", rec.Code)
	}
}

func TestMitnickAuthMiddleware_AcceptsConfiguredCredentials(t *testing.T) {
	s := newMitnickTestServer("configuser", "configpass")
	called := false
	handler := s.mitnickAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/mitnick/status", nil)
	req.Header.Set("Authorization", basicAuthHeader("configuser", "configpass"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected next handler to be called with valid configured credentials")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestNew_FailsClosedWhenMitnickCredentialsUnset(t *testing.T) {
	cfg := &config.Config{}
	_, err := New(cfg, logger.New("test"))
	if err == nil {
		t.Fatal("expected New() to return an error when Mitnick credentials are unset")
	}
}
