package goons

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nais/goons/internal/gke"
	"github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
)

var cfg struct {
	folderIDs    string
	slackWebhook string
}

func init() {
	flag.StringVar(&cfg.folderIDs, "folderIDs", os.Getenv("FOLDERS"), "GCP Folders - delimited by comma")
	flag.StringVar(&cfg.slackWebhook, "slackWebhook", os.Getenv("SLACK_WEBHOOK"), "Slack Webhook")
}

func Run(ctx context.Context) {
	log := logrus.StandardLogger()
	flag.Parse()

	if cfg.folderIDs == "" {
		log.Fatal("Folder IDs must be set")
	}

	for _, folder := range strings.Split(cfg.folderIDs, ",") {
		sccClient, err := gke.New(ctx, log)
		if err != nil {
			log.Fatal(err)
		}
		log.Infof("fetching findings for folder: %s", folder)

		result, err := sccClient.ListFindings(ctx, fmt.Sprintf("folders/%s/sources/-", folder))
		if err != nil {
			log.Fatal(err)
		}

		for _, finding := range result {
			log.Infof("Finding: %s, Severity: %s - %s: %s --- %s", finding.GetResourceName(), finding.GetSeverity(), finding.GetVulnerability(), finding.GetFindingClass(), finding.GetDescription())
		}
	}
}
