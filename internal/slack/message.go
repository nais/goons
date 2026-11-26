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
	attachments := []slackapi.Attachment{}
	blocks := []slackapi.Block{}
	headerBlock := slackapi.NewHeaderBlock(slackapi.NewTextBlockObject("plain_text", fmt.Sprintf("Findings summary from Security Command Center for %s/%s", strings.ToUpper(tenant), findingsSummary.ProjectID), false, false))
	linkBlock := slackapi.NewSectionBlock(slackapi.NewTextBlockObject("mrkdwn", "View all findings for project in <https://"+securitycommandcenter.ConsoleHost(residency)+"/security/command-center/findingsv2;filter=state%3D%22ACTIVE%22%0AAND%20NOT%20mute%3D%22MUTED%22;timeRange=P7D?location="+residency+"&project="+findingsSummary.ProjectID+"&supportedpurview=organizationId,folder,project|Security Command Center>.", false, false), nil, nil)
	blocks = append(blocks, headerBlock, linkBlock)

	for _, k := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "SEVERITY_UNSPECIFIED"} {
		var summaryText strings.Builder

		for category, count := range findingsSummary.Summary[k] {
			fmt.Fprintf(&summaryText, "%s: %d\n", category, count)
		}

		if summaryText.Len() > 0 {
			severityAttachment := slackapi.Attachment{
				Color: severityColors[k],
				Title: fmt.Sprintf("Severity %s", k),
				Text:  summaryText.String(),
			}
			attachments = append(attachments, severityAttachment)
		}
	}

	if len(attachments) == 0 {
		return nil
	}

	return []slackapi.MsgOption{
		slackapi.MsgOptionBlocks(blocks...),
		slackapi.MsgOptionAttachments(attachments...),
		slackapi.MsgOptionDisableLinkUnfurl(),
	}
}

func (s *Slack) GetFailureMessageOptions(tenant, projectID string, err error) []slackapi.MsgOption {
	text := fmt.Sprintf("Could not fetch findings for project `%s`:\n```%s```", projectID, err.Error())
	// SCC returns this misleading error when it isn't activated for the organization
	if strings.Contains(err.Error(), "Security Command Center Legacy") {
		text += "\nSecurity Command Center is probably not activated for this organization, see <https://handbook.nais.io/technical/tenant-setup/2-tenant/#enable-security-command-center|tenant setup step 2>."
	}

	headerBlock := slackapi.NewHeaderBlock(slackapi.NewTextBlockObject("plain_text", fmt.Sprintf("Failed to fetch findings from Security Command Center for %s/%s", strings.ToUpper(tenant), projectID), false, false))
	attachment := slackapi.Attachment{
		Color: severityColors["CRITICAL"],
		Title: "Error fetching findings",
		Text:  text,
	}

	return []slackapi.MsgOption{
		slackapi.MsgOptionBlocks(headerBlock),
		slackapi.MsgOptionAttachments(attachment),
		slackapi.MsgOptionDisableLinkUnfurl(),
	}
}
