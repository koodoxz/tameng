package server

import (
	"testing"

	"github.com/koodoxz/tameng/internal/config"
	"github.com/koodoxz/tameng/internal/logger"
)

func TestNew_FailsClosedWhenGodModeKeyEmpty(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			MitnickUser: "user",
			MitnickPass: "pass",
			GodModeKey:  "",
			APIKeys:     []string{"validkey"},
		},
	}
	if _, err := New(cfg, logger.New("test")); err == nil {
		t.Fatal("expected New() to return an error when GodModeKey is empty")
	}
}

func TestNew_FailsClosedWhenAPIKeysContainsEmptyString(t *testing.T) {
	// An unset SVALINN_API_KEY env var expands "${SVALINN_API_KEY}" to "",
	// so api_keys: ["${SVALINN_API_KEY}"] in configs/svalinn.yaml becomes
	// APIKeys: [""] -- which would let apiKeyMiddleware's loop match any
	// request sending no credentials at all ("" == "").
	cfg := &config.Config{
		Security: config.SecurityConfig{
			MitnickUser: "user",
			MitnickPass: "pass",
			GodModeKey:  "validgodkey",
			APIKeys:     []string{""},
		},
	}
	if _, err := New(cfg, logger.New("test")); err == nil {
		t.Fatal("expected New() to return an error when APIKeys contains an empty string")
	}
}
