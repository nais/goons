package gke

import (
	"context"
	"fmt"

	securitycenter "cloud.google.com/go/securitycenter/apiv2"
	"cloud.google.com/go/securitycenter/apiv2/securitycenterpb"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/iterator"
)

type Client struct {
	sccClient *securitycenter.Client
	log       *logrus.Logger
}

func New(ctx context.Context, log *logrus.Logger) (*Client, error) {
	client, err := securitycenter.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("securitycenter.NewClient: %w", err)
	}

	return &Client{
		sccClient: client,
		log:       log,
	}, nil
}

func (c *Client) ListFindings(ctx context.Context, sourceName string) ([]*securitycenterpb.Finding, error) {
	req := &securitycenterpb.ListFindingsRequest{
		Parent:   sourceName,
		Filter:   `state="ACTIVE"`,
		PageSize: 1000,
	}

	findings := []*securitycenterpb.Finding{}

	it := c.sccClient.ListFindings(ctx, req)
	for {
		result, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("it.Next: %w", err)
		}
		findings = append(findings, result.Finding)

	}
	return findings, nil
}
