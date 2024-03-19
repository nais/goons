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
	clusterProjectIDs string
	dataResidency     string
	slackChannel      string
	slackToken        string
	tenant            string
}

func init() {
	flag.StringVar(&cfg.clusterProjectIDs, "clusterProjectIDs", os.Getenv("CLUSTERS_PROJECTS"), "GCP Folders to fetch findings from, delimited by comma")
	flag.StringVar(&cfg.dataResidency, "dataResidency", os.Getenv("RESIDENCY"), "Data residency: eu or global")
	flag.StringVar(&cfg.slackChannel, "slackChannel", os.Getenv("SLACK_CHANNEL"), "Slack channel to send message to")
	flag.StringVar(&cfg.slackToken, "slackAPIToken", os.Getenv("SLACK_API_TOKEN"), "Slack API token")
	flag.StringVar(&cfg.tenant, "tenant", os.Getenv("TENANT"), "Tenant name")
}

func Run(ctx context.Context) {
	flag.Parse()

	if cfg.clusterProjectIDs == "" || cfg.slackToken == "" || cfg.slackChannel == "" || cfg.dataResidency == "" || cfg.tenant == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	log := logrus.StandardLogger()
	slackclient := slack.New(cfg.slackToken)
	client, err := securitycommandcenter.New(ctx, cfg.dataResidency, log)
	if err != nil {
		log.WithError(err).Fatal("create security command center client")
	}

	findings := []securitycommandcenter.Vulnerability{}
	for _, p := range strings.Split(cfg.clusterProjectIDs, ",") {
		log.Infof("fetching findings for project: %s", p)
		projectFindings, err := client.ListProjectFindings(ctx, p)
		if err != nil {
			log.WithError(err).Fatal("list folder findings")
		}
		findings = append(findings, projectFindings...)
	}

	findings = securitycommandcenter.SortVulnerabilities(findings)

	summary := securitycommandcenter.CreateSummary(findings)

	for _, v := range summary {
		msgOptions := slackclient.GetNotificationMessageOptions(cfg.tenant, cfg.dataResidency, v)
		if msgOptions == nil {
			continue
		}
		err = slackclient.SendMessage(cfg.slackChannel, msgOptions)
		if err != nil {
			log.WithError(err).Fatal("send message to slack")
		}
	}
}
