package slack

import (
	"fmt"
	"strings"

	slackapi "github.com/slack-go/slack"
)

var severityColors = map[string]string{
	"CRITICAL":             "#C30000",
	"HIGH":                 "#FFA500",
	"MEDIUM":               "#FFD700",
	"LOW":                  "#32CD32",
	"SEVERITY_UNSPECIFIED": "#808080",
}

func mrkdwn(format string, args ...any) slackapi.Block {
	return slackapi.NewSectionBlock(slackapi.NewTextBlockObject("mrkdwn", fmt.Sprintf(format, args...), false, false), nil, nil)
}

func header(format string, args ...any) slackapi.Block {
	return slackapi.NewHeaderBlock(slackapi.NewTextBlockObject("plain_text", fmt.Sprintf(format, args...), false, false))
}

func (s *Slack) GetNotificationMessageOptions(tenant, organizationId, residency string, findingsSummary map[string]map[string]int) []slackapi.MsgOption {
	attatchments := []slackapi.Attachment{}
	blocks := []slackapi.Block{}
	headerBlock := header("Findings summary from Security Command Center for %s", strings.ToUpper(tenant))

	linkBlock := mrkdwn("View all findings in <https://console.cloud.google.com/security/command-center/findingsv2?organizationId=%s&supportedpurview=organizationId,folder,project&location=%s|Security Command Center>.", organizationId, residency)
	blocks = append(blocks, headerBlock, linkBlock)

	for _, k := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "SEVERITY_UNSPECIFIED"} {
		summaryText := ""
		link := "<https://console.cloud.google.com/security/command-center/findingsv2;filter=state%3D%22ACTIVE%22%0AAND%20NOT%20mute%3D%22MUTED%22%0AAND%20severity%3D%22" + k + "%22;timeRange=P7D?organizationId=" + organizationId + "&supportedpurview=organizationId,folder,project&location=" + residency + "|View findings of " + strings.ToLower(k) + " severity in Security Command Center>.\n"

		for category, count := range findingsSummary[k] {
			summaryText += fmt.Sprintf("%s: %d\n", category, count)
		}

		text := ""
		if summaryText == "" {
			text = ":rocket: No findings! \n"
		} else {
			text = link + summaryText
		}

		severityAttachment := slackapi.Attachment{
			Color: severityColors[k],
			Title: fmt.Sprintf("Severity %s", k),
			Text:  text,
		}
		attatchments = append(attatchments, severityAttachment)
	}

	return []slackapi.MsgOption{
		slackapi.MsgOptionBlocks(blocks...),
		slackapi.MsgOptionAttachments(attatchments...),
	}
}
