package securitycommandcenter

type ProjectSummary struct {
	ProjectId string
	Summary   map[string]map[string]int
}

func CreateSummary(folderFindings []Vulnerability) map[string]ProjectSummary {
	summary := map[string]ProjectSummary{}
	for _, finding := range folderFindings {
		if _, ok := summary[finding.ProjectId]; !ok {
			summary[finding.ProjectId] = ProjectSummary{
				ProjectId: finding.ProjectId,
				Summary:   map[string]map[string]int{},
			}
		}
		if _, ok := summary[finding.ProjectId].Summary[finding.Severity]; !ok {
			summary[finding.ProjectId].Summary[finding.Severity] = map[string]int{}
		}
		summary[finding.ProjectId].Summary[finding.Severity][finding.Category]++
	}
	return summary
}
