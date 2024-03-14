package goons

import (
	"context"
	"os"
	"slices"
	"strings"

	"github.com/nais/goons/internal/scc"
	"github.com/nais/goons/internal/slack"
	"github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
)

var cfg struct {
	folderIDs     string
	slackToken    string
	dataResidency string
	tenant        string
	orgID         string
}

var severityOrder = map[string]int{
	"CRITICAL":             5,
	"HIGH":                 4,
	"MEDIUM":               3,
	"LOW":                  2,
	"SEVERITY_UNSPECIFIED": 1,
}

func init() {
	flag.StringVar(&cfg.folderIDs, "folderIDs", os.Getenv("FOLDERS"), "GCP Folders - delimited by comma")
	flag.StringVar(&cfg.dataResidency, "dataResidency", os.Getenv("RESIDENCY"), "Data residency")
	flag.StringVar(&cfg.slackToken, "slackToken", os.Getenv("SLACK_API_TOKEN"), "Slack Webhook")
	flag.StringVar(&cfg.tenant, "tenant", os.Getenv("TENANT"), "Tenant")
	flag.StringVar(&cfg.orgID, "orgID", os.Getenv("ORG_ID"), "Organization ID")
}

func Run(ctx context.Context) {
	log := logrus.StandardLogger()
	slack := slack.New(cfg.slackToken)

	flag.Parse()

	if cfg.folderIDs == "" {
		log.Fatal("Folder IDs must be set")
	}

	folderFindings := []scc.Vulnerability{}

	for _, folder := range strings.Split(cfg.folderIDs, ",") {
		sccClient, err := scc.New(ctx, cfg.dataResidency, log)
		if err != nil {
			log.Fatal(err)
		}
		log.Infof("fetching findings for folder: %s", folder)
		findings, err := sccClient.ListFolderFindings(ctx, folder)
		if err != nil {
			log.Fatal(err)
		}
		folderFindings = append(folderFindings, findings...)
	}

	folderFindings = sortVulnerabilities(folderFindings)

	findingsSummary := map[string]map[string]int{}

	for _, finding := range folderFindings {
		if _, ok := findingsSummary[finding.Severity]; !ok {
			findingsSummary[finding.Severity] = map[string]int{}
		}

		findingsSummary[finding.Severity][finding.Category]++
	}

	msgOptions := slack.GetNotificationMessageOptions(cfg.tenant, cfg.orgID, cfg.dataResidency, findingsSummary)
	err := slack.SendMessage("scc-alerts", msgOptions)
	if err != nil {
		log.Fatal(err)
	}
}

func sortVulnerabilities(results []scc.Vulnerability) []scc.Vulnerability {
	slices.SortFunc(results, func(i, j scc.Vulnerability) int {
		if i.Severity == j.Severity {
			return strings.Compare(i.Category, j.Category)
		}
		if severityOrder[i.Severity] < severityOrder[j.Severity] {
			return 1
		} else if severityOrder[i.Severity] > severityOrder[j.Severity] {
			return -1
		}
		return 0
	})
	return results
}
