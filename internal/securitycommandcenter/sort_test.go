package securitycommandcenter_test

import (
	"testing"

	"github.com/nais/goons/internal/securitycommandcenter"
)

func TestSortVulnerabilities(t *testing.T) {
	tests := []struct {
		name     string
		input    []securitycommandcenter.Vulnerability
		expected []securitycommandcenter.Vulnerability
	}{
		{
			name: "sorts by severity",
			input: []securitycommandcenter.Vulnerability{
				{Severity: "LOW", Category: "A", FindingUrl: "http://example.com"},
				{Severity: "MEDIUM", Category: "B", FindingUrl: "http://example.com"},
				{Severity: "CRITICAL", Category: "C", FindingUrl: "http://example.com"},
				{Severity: "HIGH", Category: "D", FindingUrl: "http://example.com"},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "E", FindingUrl: "http://example.com"},
			},
			expected: []securitycommandcenter.Vulnerability{
				{Severity: "CRITICAL", Category: "C", FindingUrl: "http://example.com"},
				{Severity: "HIGH", Category: "D", FindingUrl: "http://example.com"},
				{Severity: "MEDIUM", Category: "B", FindingUrl: "http://example.com"},
				{Severity: "LOW", Category: "A", FindingUrl: "http://example.com"},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "E", FindingUrl: "http://example.com"},
			},
		},
		{
			name: "sorts by severity and category",
			input: []securitycommandcenter.Vulnerability{
				{Severity: "LOW", Category: "A", FindingUrl: "http://example.com"},
				{Severity: "LOW", Category: "B", FindingUrl: "http://example.com"},
				{Severity: "MEDIUM", Category: "A", FindingUrl: "http://example.com"},
				{Severity: "MEDIUM", Category: "B", FindingUrl: "http://example.com"},
				{Severity: "CRITICAL", Category: "A", FindingUrl: "http://example.com"},
				{Severity: "CRITICAL", Category: "B", FindingUrl: "http://example.com"},
				{Severity: "HIGH", Category: "A", FindingUrl: "http://example.com"},
				{Severity: "HIGH", Category: "B", FindingUrl: "http://example.com"},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "A", FindingUrl: "http://example.com"},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "B", FindingUrl: "http://example.com"},
			},
			expected: []securitycommandcenter.Vulnerability{
				{Severity: "CRITICAL", Category: "A", FindingUrl: "http://example.com"},
				{Severity: "CRITICAL", Category: "B", FindingUrl: "http://example.com"},
				{Severity: "HIGH", Category: "A", FindingUrl: "http://example.com"},
				{Severity: "HIGH", Category: "B", FindingUrl: "http://example.com"},
				{Severity: "MEDIUM", Category: "A", FindingUrl: "http://example.com"},
				{Severity: "MEDIUM", Category: "B", FindingUrl: "http://example.com"},
				{Severity: "LOW", Category: "A", FindingUrl: "http://example.com"},
				{Severity: "LOW", Category: "B", FindingUrl: "http://example.com"},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "A", FindingUrl: "http://example.com"},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "B", FindingUrl: "http://example.com"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := securitycommandcenter.SortVulnerabilities(tt.input)
			if len(actual) != len(tt.expected) {
				t.Errorf("expected %d results, got %d", len(tt.expected), len(actual))
			}
			for i := range actual {
				if actual[i] != tt.expected[i] {
					t.Errorf("expected %v, got %v", tt.expected[i], actual[i])
				}
			}
		})
	}
}
