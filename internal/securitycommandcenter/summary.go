package securitycommandcenter

func CreateSummary(folderFindings []Vulnerability) map[string]map[string]int {
	findingsSummary := map[string]map[string]int{}
	for _, finding := range folderFindings {
		if _, ok := findingsSummary[finding.Severity]; !ok {
			findingsSummary[finding.Severity] = map[string]int{}
		}
		findingsSummary[finding.Severity][finding.Category]++
	}
	return findingsSummary
}
