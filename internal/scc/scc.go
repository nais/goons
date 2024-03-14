package scc

import (
	"context"
	"fmt"
	"net/url"

	securitycenter "cloud.google.com/go/securitycenter/apiv2"
	"cloud.google.com/go/securitycenter/apiv2/securitycenterpb"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/iterator"
)

type Vulnerability struct {
	Severity   string
	Category   string
	FindingUrl url.URL
}

type Client struct {
	sccClient *securitycenter.Client
	log       *logrus.Logger
	residency string
}

func New(ctx context.Context, residency string, log *logrus.Logger) (*Client, error) {
	client, err := securitycenter.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("securitycenter.NewClient: %w", err)
	}

	return &Client{
		sccClient: client,
		log:       log,
		residency: residency,
	}, nil
}

func (c *Client) ListFindings(ctx context.Context, sourceName string) ([]*securitycenterpb.Finding, error) {
	req := &securitycenterpb.ListFindingsRequest{
		Parent: sourceName,
		Filter: `state="ACTIVE"`,
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

func (c *Client) ListFolderFindings(ctx context.Context, folder string) ([]Vulnerability, error) {
	ret := []Vulnerability{}
	findings, err := c.ListFindings(ctx, fmt.Sprintf("folders/%s/sources/-/locations/%s", folder, c.residency))
	if err != nil {
		return nil, err
	}

	for _, finding := range findings {
		ret = append(ret, Vulnerability{
			Severity: finding.GetSeverity().String(),
			Category: finding.GetCategory(),
			FindingUrl: url.URL{
				Scheme: "https",
				Host:   "console.cloud.google.com",
				Path:   fmt.Sprintf("security/command-center/findingsv2;name=%s;", finding.GetName()),
			},
		})
	}
	return ret, nil
}
