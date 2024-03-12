package goons

import (
	"context"

	"github.com/davecgh/go-spew/spew"
	"github.com/nais/goons/internal/gke"
	"github.com/sirupsen/logrus"
)

func Run(ctx context.Context) {
	log := logrus.StandardLogger()
	log.Info("Hello, Goons!")

	sccClient, err := gke.New(log)
	if err != nil {
		log.Fatal(err)
	}

	result, err := sccClient.ListFindings(ctx, "folders/201134087427/sources/-")
	if err != nil {
		log.Fatal(err)
	}
	spew.Dump(result)

}
