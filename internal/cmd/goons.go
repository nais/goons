package goons

import (
	"context"
	"fmt"
	"os"

	"github.com/nais/goons/internal/gke"
	"github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
)

var cfg struct {
	orgID        string
	folderIDs    string
	slackWebhook string
}

func init() {
	flag.StringVar(&cfg.orgID, "orgID", os.Getenv("ORGANIZATION_ID"), "GCP Organzation ID")
	flag.StringVar(&cfg.folderIDs, "folderIDs", os.Getenv("FOLDER_ID"), "GCP Folder")
	flag.StringVar(&cfg.slackWebhook, "slackWebhook", os.Getenv("SLACK_WEBHOOK"), "Slack Webhook")
}

func Run(ctx context.Context) {
	log := logrus.StandardLogger()
	flag.Parse()

	if cfg.orgID == "" && cfg.folderIDs == "" {
		log.Fatal("Organization ID or Folder ID must be set")
	}

	sccClient, err := gke.New(ctx, log)
	if err != nil {
		log.Fatal(err)
	}

	if cfg.orgID != "" {
		result, err := sccClient.ListFindings(ctx, fmt.Sprintf("organizations/%s/sources/-", cfg.orgID))
		if err != nil {
			log.Fatal(err)
		}

		for _, finding := range result {
			log.Infof("Finding: %s, Severity: %s - %s: %s --- %s", finding.GetResourceName(), finding.GetSeverity(), finding.GetVulnerability(), finding.GetFindingClass(), finding.GetDescription())
		}
	}
}
