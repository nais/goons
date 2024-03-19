package slack

import (
	"fmt"
	"strings"

	"github.com/nais/goons/internal/securitycommandcenter"
	slackapi "github.com/slack-go/slack"
)

var severityColors = map[string]string{
	"CRITICAL":             "#C30000",
	"HIGH":                 "#FFA500",
	"MEDIUM":               "#FFD700",
	"LOW":                  "#32CD32",
	"SEVERITY_UNSPECIFIED": "#808080",
}

func (s *Slack) GetNotificationMessageOptions(tenant, residency string, findingsSummary securitycommandcenter.ProjectSummary) []slackapi.MsgOption {
	attatchments := []slackapi.Attachment{}
	blocks := []slackapi.Block{}
	headerBlock := slackapi.NewHeaderBlock(slackapi.NewTextBlockObject("plain_text", fmt.Sprintf("Findings summary from Security Command Center for %s/%s", strings.ToUpper(tenant), findingsSummary.ProjectId), false, false))
	linkBlock := slackapi.NewSectionBlock(slackapi.NewTextBlockObject("mrkdwn", "View all findings for project in <https://console.cloud.google.com/security/command-center/findingsv2;filter=state%3D%22ACTIVE%22%0AAND%20NOT%20mute%3D%22MUTED%22;timeRange=P7D?location="+residency+"&project="+findingsSummary.ProjectId+"&supportedpurview=organizationId,folder,project|Security Command Center>.", false, false), nil, nil)
	blocks = append(blocks, headerBlock, linkBlock)

	for _, k := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "SEVERITY_UNSPECIFIED"} {
		summaryText := ""

		for category, count := range findingsSummary.Summary[k] {
			summaryText += fmt.Sprintf("%s: %d\n", category, count)
		}

		if summaryText != "" {
			severityAttachment := slackapi.Attachment{
				Color: severityColors[k],
				Title: fmt.Sprintf("Severity %s", k),
				Text:  summaryText,
			}
			attatchments = append(attatchments, severityAttachment)
		}
	}

	if len(attatchments) == 0 {
		return nil
	}

	return []slackapi.MsgOption{
		slackapi.MsgOptionBlocks(blocks...),
		slackapi.MsgOptionAttachments(attatchments...),
		slackapi.MsgOptionDisableLinkUnfurl(),
	}
}
