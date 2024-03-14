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

func (s *Slack) GetNotificationMessageOptions(tenant string, findingsSummary map[string]map[string]int) []slackapi.MsgOption {
	attatchments := []slackapi.Attachment{}

	headerBlock := header("Findings from Security Command Center for %s", strings.ToUpper(tenant))

	for severity, categories := range findingsSummary {
		tmp := ""
		for category, count := range categories {
			tmp += fmt.Sprintf("%s: %d\n", category, count)
		}

		severityAttachment := slackapi.Attachment{
			Color: severityColors[severity],
			Title: fmt.Sprintf("Severity %s", severity),
			Text:  tmp,
		}
		attatchments = append(attatchments, severityAttachment)

	}

	linkBlock := mrkdwn("View all findings in <%s|Security Command Center>", "https://vg.no")

	return []slackapi.MsgOption{
		slackapi.MsgOptionBlocks(headerBlock, linkBlock),
		slackapi.MsgOptionAttachments(attatchments...),
	}
}
