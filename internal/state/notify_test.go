package state

import (
	"strings"
	"testing"
)

func TestNotifyConfigValidation(t *testing.T) {
	// Disabled empty config is valid
	s := NewDefaultState(RoleClient)
	if err := s.Validate(); err != nil {
		t.Fatalf("default state with disabled notify should be valid: %v", err)
	}

	// Enabled with no channels must fail
	s.System.Notify.Enabled = true
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "at least one channel") {
		t.Fatalf("expected channel required error, got %v", err)
	}

	// Valid webhook URL passes
	s.System.Notify.WebhookURL = "https://hooks.example.com/dex"
	if err := s.Validate(); err != nil {
		t.Fatalf("valid webhook_url rejected: %v", err)
	}

	// Invalid webhook scheme rejected
	s.System.Notify.WebhookURL = "ftp://hooks.example.com/dex"
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "webhook_url") {
		t.Fatalf("expected invalid webhook_url error, got %v", err)
	}

	// Telegram token without chat_id rejected
	s.System.Notify.WebhookURL = ""
	s.System.Notify.TelegramBotToken = "123456:ABCDEF"
	s.System.Notify.TelegramChatID = ""
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "telegram_bot_token") {
		t.Fatalf("expected telegram pair error, got %v", err)
	}

	// Valid Telegram pair passes
	s.System.Notify.TelegramChatID = "-1001234567890"
	if err := s.Validate(); err != nil {
		t.Fatalf("valid telegram config rejected: %v", err)
	}

	// Control characters rejected
	s.System.Notify.TelegramChatID = "123\n456"
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "control character") {
		t.Fatalf("expected control char error, got %v", err)
	}
}
