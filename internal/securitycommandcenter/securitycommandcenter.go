package securitycommandcenter

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	securitycenter "cloud.google.com/go/securitycenter/apiv2"
	"cloud.google.com/go/securitycenter/apiv2/securitycenterpb"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/iterator"
)

type Vulnerability struct {
	Severity   string
	Category   string
	FindingUrl string
	ProjectId  string
}

type Client struct {
	client    *securitycenter.Client
	log       *logrus.Logger
	residency string
}

func New(ctx context.Context, residency string, log *logrus.Logger) (*Client, error) {
	client, err := securitycenter.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("securitycenter.NewClient: %w", err)
	}

	return &Client{
		client:    client,
		log:       log,
		residency: residency,
	}, nil
}

func (c *Client) listFindings(ctx context.Context, sourceName string) ([]*securitycenterpb.Finding, error) {
	// Get all findings from the last 7 days
	filterDate := time.Now().AddDate(0, 0, -7).Format("2006-01-02")
	req := &securitycenterpb.ListFindingsRequest{
		Parent: sourceName,
		Filter: fmt.Sprintf(`state="ACTIVE" AND NOT mute="MUTED" AND event_time >= "%s"`, filterDate),
	}

	var findings []*securitycenterpb.Finding

	it := c.client.ListFindings(ctx, req)
	for {
		result, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("it.Next: %w", err)
		}
		findings = append(findings, result.Finding)

	}
	return findings, nil
}

func (c *Client) ListProjectFindings(ctx context.Context, project string) ([]Vulnerability, error) {
	var ret []Vulnerability
	findings, err := c.listFindings(ctx, fmt.Sprintf("projects/%s/sources/-/locations/%s", project, c.residency))
	if err != nil {
		return nil, err
	}

	for _, finding := range findings {
		ret = append(ret, Vulnerability{
			Severity:   finding.GetSeverity().String(),
			Category:   finding.GetCategory(),
			FindingUrl: "https://console.cloud.google.com/security/command-center/findingsv2;name=" + url.PathEscape(finding.GetName()) + ";filter=state%3D%22ACTIVE%22%0AAND%20NOT%20mute%3D%22MUTED%22;timeRange=allTime?referrer=search&project=" + project,
			ProjectId:  project,
		})
	}

	return ret, nil
}
