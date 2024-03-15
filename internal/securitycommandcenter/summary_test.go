package securitycommandcenter_test

import (
	"reflect"
	"testing"

	"github.com/nais/goons/internal/securitycommandcenter"
)

func TestCreateSummary(t *testing.T) {
	tests := []struct {
		name     string
		input    []securitycommandcenter.Vulnerability
		expected map[string]map[string]int
	}{
		{
			name: "creates a summary",
			input: []securitycommandcenter.Vulnerability{
				{Severity: "LOW", Category: "A"},
				{Severity: "MEDIUM", Category: "B"},
				{Severity: "CRITICAL", Category: "C"},
				{Severity: "CRITICAL", Category: "F"},
				{Severity: "CRITICAL", Category: "F"},
				{Severity: "CRITICAL", Category: "F"},
				{Severity: "HIGH", Category: "D"},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "E"},
				{Severity: "LOW", Category: "A"},
				{Severity: "MEDIUM", Category: "B"},
				{Severity: "CRITICAL", Category: "C"},
				{Severity: "HIGH", Category: "D"},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "A"},
			},
			expected: map[string]map[string]int{
				"CRITICAL":             {"C": 2, "F": 3},
				"HIGH":                 {"D": 2},
				"MEDIUM":               {"B": 2},
				"LOW":                  {"A": 2},
				"SEVERITY_UNSPECIFIED": {"A": 1, "E": 1},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := securitycommandcenter.CreateSummary(tt.input)
			if !reflect.DeepEqual(actual, tt.expected) {
				t.Errorf("CreateSummary(%v) = %v, want %v", tt.input, actual, tt.expected)
			}
		})
	}
}
