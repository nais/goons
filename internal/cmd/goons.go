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
	flag.StringVar(&cfg.clusterProjectIDs, "clusterProjectIDs", os.Getenv("CLUSTER_PROJECTS"), "GCP projects to fetch findings from, delimited by comma")
	flag.StringVar(&cfg.dataResidency, "dataResidency", os.Getenv("RESIDENCY"), "Data residency should be either 'eu' or 'global'")
	flag.StringVar(&cfg.slackChannel, "slackChannel", os.Getenv("SLACK_CHANNEL"), "Slack channel to send message to")
	flag.StringVar(&cfg.slackToken, "slackAPIToken", os.Getenv("SLACK_API_TOKEN"), "Slack API token")
	flag.StringVar(&cfg.tenant, "tenant", os.Getenv("TENANT"), "Tenant name")
}

func Run(ctx context.Context) {
	log := logrus.StandardLogger()

	flag.Parse()

	var missing []string
	if cfg.clusterProjectIDs == "" {
		missing = append(missing, "clusterProjectIDs")
	}
	if cfg.slackToken == "" {
		missing = append(missing, "slackAPIToken")
	}
	if cfg.slackChannel == "" {
		missing = append(missing, "slackChannel")
	}
	if cfg.tenant == "" {
		missing = append(missing, "tenant")
	}
	if cfg.dataResidency == "" {
		missing = append(missing, "dataResidency")
	}
	if len(missing) > 0 {
		log.Errorf("missing required flags: %s", strings.Join(missing, ", "))
		flag.PrintDefaults()
		os.Exit(1)
	}

	cfg.dataResidency = strings.ToLower(cfg.dataResidency)
	if cfg.dataResidency != "eu" && cfg.dataResidency != "global" {
		log.Errorf("invalid dataResidency: %q; must be 'eu' or 'global'", cfg.dataResidency)
		flag.PrintDefaults()
		os.Exit(1)
	}

	slackclient := slack.New(cfg.slackToken)

	client, err := securitycommandcenter.New(ctx, cfg.dataResidency, log)
	if err != nil {
		log.WithError(err).Fatal("create security command center client")
	}

	findings := []securitycommandcenter.Vulnerability{}
	for projectID := range strings.SplitSeq(cfg.clusterProjectIDs, ",") {
		projectID = strings.TrimSpace(projectID)
		if projectID == "" {
			continue
		}
		log.Infof("fetching findings for project: %s", projectID)
		projectFindings, err := client.ListProjectFindings(ctx, projectID)
		if err != nil {
			log.WithError(err).Fatal("list project findings")
		}
		findings = append(findings, projectFindings...)
	}

	findings = securitycommandcenter.SortVulnerabilities(findings)

	summaries := securitycommandcenter.CreateSummary(findings)

	for projectID, summary := range summaries {
		msgOptions := slackclient.GetNotificationMessageOptions(cfg.tenant, cfg.dataResidency, summary)
		if msgOptions == nil {
			continue
		}
		log.Info("sending message to slack for project: ", projectID)
		err = slackclient.SendMessage(cfg.slackChannel, msgOptions)
		if err != nil {
			log.WithError(err).Fatal("send message to slack")
		}
	}
}
