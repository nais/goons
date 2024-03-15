package securitycommandcenter

import (
	"slices"
	"strings"
)

var SeverityOrder = map[string]int{
	"CRITICAL":             5,
	"HIGH":                 4,
	"MEDIUM":               3,
	"LOW":                  2,
	"SEVERITY_UNSPECIFIED": 1,
}

func SortVulnerabilities(results []Vulnerability) []Vulnerability {
	slices.SortFunc(results, func(i, j Vulnerability) int {
		if i.Severity == j.Severity {
			return strings.Compare(i.Category, j.Category)
		}
		if SeverityOrder[i.Severity] < SeverityOrder[j.Severity] {
			return 1
		} else if SeverityOrder[i.Severity] > SeverityOrder[j.Severity] {
			return -1
		}
		return 0
	})
	return results
}
