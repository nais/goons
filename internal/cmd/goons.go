package goons

import (
	"context"

	"github.com/sirupsen/logrus"
)

func Run(ctx context.Context) {
	log := logrus.StandardLogger()
	log.Info("Hello, Goons!")
}
