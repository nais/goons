package goons

import (
	"context"
	"os"
	"strings"

	"github.com/nais/goons/internal/securitycommandcenter"
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

func init() {
	flag.StringVar(&cfg.dataResidency, "dataResidency", os.Getenv("RESIDENCY"), "Data residency: eu or global")
	flag.StringVar(&cfg.folderIDs, "folderIDs", os.Getenv("FOLDERS"), "GCP Folders to fetch findings from, delimited by comma")
	flag.StringVar(&cfg.orgID, "orgID", os.Getenv("ORG_ID"), "Organization ID")
	flag.StringVar(&cfg.slackToken, "slackAPIToken", os.Getenv("SLACK_API_TOKEN"), "Slack API token")
	flag.StringVar(&cfg.tenant, "tenant", os.Getenv("TENANT"), "Tenant name")
}

func Run(ctx context.Context) {
	flag.Parse()

	if cfg.folderIDs == "" || cfg.slackToken == "" || cfg.dataResidency == "" || cfg.tenant == "" || cfg.orgID == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	log := logrus.StandardLogger()
	slackclient := slack.New(cfg.slackToken)
	client, err := securitycommandcenter.New(ctx, cfg.dataResidency, log)
	if err != nil {
		log.WithError(err).Fatal("create security command center client")
	}

	folderFindings := []securitycommandcenter.Vulnerability{}
	for _, folder := range strings.Split(cfg.folderIDs, ",") {
		log.Infof("fetching findings for folder: %s", folder)
		findings, err := client.ListFolderFindings(ctx, folder)
		if err != nil {
			log.WithError(err).Fatal("list folder findings")
		}
		folderFindings = append(folderFindings, findings...)
	}

	folderFindings = securitycommandcenter.SortVulnerabilities(folderFindings)

	findingsSummary := securitycommandcenter.CreateSummary(folderFindings)

	msgOptions := slackclient.GetNotificationMessageOptions(cfg.tenant, cfg.orgID, cfg.dataResidency, findingsSummary)
	err = slackclient.SendMessage("scc-alerts", msgOptions)
	if err != nil {
		log.WithError(err).Fatal("send message to slack")
	}
}
