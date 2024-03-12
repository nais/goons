package gke

import (
	"context"
	"fmt"

	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/iterator"
)

type Client struct {
	sccClient *securitycenter.Client
	log       *logrus.Logger
}

func New(log *logrus.Logger, sccClient *securitycenter.Client) (*Client, error) {
	ctx := context.Background()
	client, err := securitycenter.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("securitycenter.NewClient: %w", err)
	}
	defer client.Close()

	return &Client{
		sccClient: sccClient,
		log:       log,
	}, nil
}

func (c *Client) Close() error {
	return c.sccClient.Close()
}

func (c *Client) ListFindings(ctx context.Context, sourceName string) ([]*securitycenterpb.Finding, error) {
	req := &securitycenterpb.ListFindingsRequest{
		Parent: sourceName,
		Filter: `state="ACTIVE"`,
	}

	findings := make([]*securitycenterpb.Finding, 10)

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
