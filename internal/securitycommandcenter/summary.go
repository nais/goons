package securitycommandcenter

type ProjectSummary struct {
	ProjectID string
	Summary   map[string]map[string]int
}

func CreateSummary(folderFindings []Vulnerability) map[string]ProjectSummary {
	summary := map[string]ProjectSummary{}
	for _, finding := range folderFindings {
		if _, ok := summary[finding.ProjectID]; !ok {
			summary[finding.ProjectID] = ProjectSummary{
				ProjectID: finding.ProjectID,
				Summary:   map[string]map[string]int{},
			}
		}
		if _, ok := summary[finding.ProjectID].Summary[finding.Severity]; !ok {
			summary[finding.ProjectID].Summary[finding.Severity] = map[string]int{}
		}
		summary[finding.ProjectID].Summary[finding.Severity][finding.Category]++
	}
	return summary
}
