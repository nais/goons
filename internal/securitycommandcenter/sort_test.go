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
				{Severity: "LOW", Category: "A", FindingURL: "http://example.com"},
				{Severity: "MEDIUM", Category: "B", FindingURL: "http://example.com"},
				{Severity: "CRITICAL", Category: "C", FindingURL: "http://example.com"},
				{Severity: "HIGH", Category: "D", FindingURL: "http://example.com"},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "E", FindingURL: "http://example.com"},
			},
			expected: []securitycommandcenter.Vulnerability{
				{Severity: "CRITICAL", Category: "C", FindingURL: "http://example.com"},
				{Severity: "HIGH", Category: "D", FindingURL: "http://example.com"},
				{Severity: "MEDIUM", Category: "B", FindingURL: "http://example.com"},
				{Severity: "LOW", Category: "A", FindingURL: "http://example.com"},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "E", FindingURL: "http://example.com"},
			},
		},
		{
			name: "sorts by severity and category",
			input: []securitycommandcenter.Vulnerability{
				{Severity: "LOW", Category: "A", FindingURL: "http://example.com"},
				{Severity: "LOW", Category: "B", FindingURL: "http://example.com"},
				{Severity: "MEDIUM", Category: "A", FindingURL: "http://example.com"},
				{Severity: "MEDIUM", Category: "B", FindingURL: "http://example.com"},
				{Severity: "CRITICAL", Category: "A", FindingURL: "http://example.com"},
				{Severity: "CRITICAL", Category: "B", FindingURL: "http://example.com"},
				{Severity: "HIGH", Category: "A", FindingURL: "http://example.com"},
				{Severity: "HIGH", Category: "B", FindingURL: "http://example.com"},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "A", FindingURL: "http://example.com"},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "B", FindingURL: "http://example.com"},
			},
			expected: []securitycommandcenter.Vulnerability{
				{Severity: "CRITICAL", Category: "A", FindingURL: "http://example.com"},
				{Severity: "CRITICAL", Category: "B", FindingURL: "http://example.com"},
				{Severity: "HIGH", Category: "A", FindingURL: "http://example.com"},
				{Severity: "HIGH", Category: "B", FindingURL: "http://example.com"},
				{Severity: "MEDIUM", Category: "A", FindingURL: "http://example.com"},
				{Severity: "MEDIUM", Category: "B", FindingURL: "http://example.com"},
				{Severity: "LOW", Category: "A", FindingURL: "http://example.com"},
				{Severity: "LOW", Category: "B", FindingURL: "http://example.com"},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "A", FindingURL: "http://example.com"},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "B", FindingURL: "http://example.com"},
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
