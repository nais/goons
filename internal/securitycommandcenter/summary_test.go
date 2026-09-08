package securitycommandcenter_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nais/goons/internal/securitycommandcenter"
)

func TestCreateSummary(t *testing.T) {
	tests := []struct {
		name     string
		input    []securitycommandcenter.Vulnerability
		expected map[string]securitycommandcenter.ProjectSummary
	}{
		{
			name: "creates a summary",
			input: []securitycommandcenter.Vulnerability{
				{Severity: "LOW", Category: "A", ProjectID: "the-project-id-a"},
				{Severity: "MEDIUM", Category: "B", ProjectID: "the-project-id-a"},
				{Severity: "CRITICAL", Category: "C", ProjectID: "the-project-id-a"},
				{Severity: "CRITICAL", Category: "F", ProjectID: "the-project-id-a"},
				{Severity: "CRITICAL", Category: "F", ProjectID: "the-project-id-b"},
				{Severity: "CRITICAL", Category: "F", ProjectID: "the-project-id-a"},
				{Severity: "HIGH", Category: "D", ProjectID: "the-project-id-a"},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "E", ProjectID: "the-project-id-a"},
				{Severity: "LOW", Category: "A", ProjectID: "the-project-id-a"},
				{Severity: "MEDIUM", Category: "B", ProjectID: "the-project-id-a"},
				{Severity: "CRITICAL", Category: "C", ProjectID: "the-project-id-a"},
				{Severity: "HIGH", Category: "D", ProjectID: "the-project-id-a"},
				{Severity: "SEVERITY_UNSPECIFIED", Category: "A", ProjectID: "the-project-id-a"},
			},
			expected: map[string]securitycommandcenter.ProjectSummary{
				"the-project-id-a": {
					ProjectID: "the-project-id-a",
					Summary: map[string]map[string]int{
						"CRITICAL":             {"C": 2, "F": 2},
						"HIGH":                 {"D": 2},
						"LOW":                  {"A": 2},
						"MEDIUM":               {"B": 2},
						"SEVERITY_UNSPECIFIED": {"A": 1, "E": 1},
					},
				},
				"the-project-id-b": {
					ProjectID: "the-project-id-b",
					Summary:   map[string]map[string]int{"CRITICAL": {"F": 1}},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := securitycommandcenter.CreateSummary(tt.input)
			if diff := cmp.Diff(actual, tt.expected); diff != "" {
				t.Errorf("CreateSummary() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
