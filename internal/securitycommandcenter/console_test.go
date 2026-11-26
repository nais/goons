package securitycommandcenter_test

import (
	"testing"

	"github.com/nais/goons/internal/securitycommandcenter"
)

func TestConsoleHost(t *testing.T) {
	tests := []struct {
		name      string
		residency string
		expected  string
	}{
		{
			name:      "eu residency uses jurisdictional console",
			residency: "eu",
			expected:  "console.eu.cloud.google.com",
		},
		{
			name:      "global residency uses standard console",
			residency: "global",
			expected:  "console.cloud.google.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if actual := securitycommandcenter.ConsoleHost(tt.residency); actual != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, actual)
			}
		})
	}
}
