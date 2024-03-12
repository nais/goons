package goons

import (
	"context"

	"github.com/nais/goons/internal/gke"
	"github.com/sirupsen/logrus"
)

func Run(ctx context.Context) {
	log := logrus.StandardLogger()
	log.Info("Hello, Goons!")

	sccClient, err := gke.New(ctx, log)
	if err != nil {
		log.Fatal(err)
	}

	result, err := sccClient.ListFindings(ctx, "organizations/139592330668/sources/-")
	if err != nil {
		log.Fatal(err)
	}

	for _, finding := range result {
		log.Infof("Finding: %s, Severity: %s - %s: %s --- %s\n%s", finding.GetResourceName(), finding.GetSeverity(), finding.GetVulnerability(), finding.GetFindingClass(), finding.GetDescription(), finding.GetSourceProperties())
	}

}
