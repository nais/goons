package securitycommandcenter_test

import (
	"net/url"
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
				{Severity: "LOW", Category: "A", FindingUrl: url.URL{}},
				{Severity: "MEDIUM", Category: "B", FindingUrl: url.URL{}},
				{Severity: "CRITICAL", Category: "C", FindingUrl: url.URL{}},
				{Severity: "HIGH", Category: "D", FindingUrl: url.URL{}},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "E", FindingUrl: url.URL{}},
			},
			expected: []securitycommandcenter.Vulnerability{
				{Severity: "CRITICAL", Category: "C", FindingUrl: url.URL{}},
				{Severity: "HIGH", Category: "D", FindingUrl: url.URL{}},
				{Severity: "MEDIUM", Category: "B", FindingUrl: url.URL{}},
				{Severity: "LOW", Category: "A", FindingUrl: url.URL{}},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "E", FindingUrl: url.URL{}},
			},
		},
		{
			name: "sorts by severity and category",
			input: []securitycommandcenter.Vulnerability{
				{Severity: "LOW", Category: "A", FindingUrl: url.URL{}},
				{Severity: "LOW", Category: "B", FindingUrl: url.URL{}},
				{Severity: "MEDIUM", Category: "A", FindingUrl: url.URL{}},
				{Severity: "MEDIUM", Category: "B", FindingUrl: url.URL{}},
				{Severity: "CRITICAL", Category: "A", FindingUrl: url.URL{}},
				{Severity: "CRITICAL", Category: "B", FindingUrl: url.URL{}},
				{Severity: "HIGH", Category: "A", FindingUrl: url.URL{}},
				{Severity: "HIGH", Category: "B", FindingUrl: url.URL{}},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "A", FindingUrl: url.URL{}},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "B", FindingUrl: url.URL{}},
			},
			expected: []securitycommandcenter.Vulnerability{
				{Severity: "CRITICAL", Category: "A", FindingUrl: url.URL{}},
				{Severity: "CRITICAL", Category: "B", FindingUrl: url.URL{}},
				{Severity: "HIGH", Category: "A", FindingUrl: url.URL{}},
				{Severity: "HIGH", Category: "B", FindingUrl: url.URL{}},
				{Severity: "MEDIUM", Category: "A", FindingUrl: url.URL{}},
				{Severity: "MEDIUM", Category: "B", FindingUrl: url.URL{}},
				{Severity: "LOW", Category: "A", FindingUrl: url.URL{}},
				{Severity: "LOW", Category: "B", FindingUrl: url.URL{}},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "A", FindingUrl: url.URL{}},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "B", FindingUrl: url.URL{}},
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
