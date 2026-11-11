package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"
)

const Origin = "cs-escalation-controller"

// Client uses CrowdSec's machine-authenticated client, not a bouncer API key.
type Client struct {
	api *apiclient.ApiClient
}

func NewClient(address, username, password, userAgent string) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(address, "/") + "/")
	if err != nil {
		return nil, err
	}
	c := apiclient.NewClient(&apiclient.Config{
		URL:           u,
		MachineID:     username,
		Password:      strfmt.Password(password),
		VersionPrefix: "v1",
		UserAgent:     userAgent,
	})
	c.GetClient().Timeout = 30 * time.Second
	// This policy covers API requests. The SDK uses a separate client for login.
	c.GetClient().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// POST /alerts has no idempotency key. Retry only authentication rejections,
	// which happen before the write handler runs, never ambiguous 5xx responses.
	c.GetClient().Transport.(*apiclient.JWTTransport).RetryConfig = apiclient.NewRetryConfig(
		apiclient.WithStatusCodeConfig(http.StatusUnauthorized, 2, false, true),
		apiclient.WithStatusCodeConfig(http.StatusForbidden, 2, false, true),
	)
	return &Client{
		api: c,
	}, nil
}

func (c *Client) Heartbeat(ctx context.Context) error {
	_, _, err := c.api.HeartBeat.Ping(ctx)
	return err
}

func (c *Client) Alerts(ctx context.Context) ([]*models.Alert, time.Time, error) {
	started := time.Now().UTC()
	alerts, _, err := c.api.Alerts.List(ctx, apiclient.AlertsListOpts{
		Limit:                new(0), // LAPI paginates internally; zero requests all matching alerts.
		ActiveDecisionEquals: new(true),
		TypeEquals:           types.DecisionTypeBan,
		OriginEquals:         types.CrowdSecOrigin,
		IncludeCAPI:          new(false),
		IncludeSimulated:     new(false),
	})
	if err != nil {
		return nil, started, err
	}
	return *alerts, started, nil
}

func (c *Client) Alert(ctx context.Context, id int64) (*models.Alert, error) {
	a, _, err := c.api.Alerts.GetByID(ctx, int(id))
	return a, err
}

func (c *Client) Allowlisted(ctx context.Context, ip string) (bool, error) {
	allowed, _, err := c.api.Allowlists.CheckIfAllowlisted(ctx, ip)
	return allowed, err
}

func (c *Client) Ban(ctx context.Context, op Operation, now time.Time) error {
	duration := op.Until.Sub(now).Truncate(time.Second)
	if duration <= 0 {
		return errors.New("escalation expired before submission")
	}
	scenario := fmt.Sprintf("%s/%d", Origin, op.AlertID)
	a := &models.Alert{
		StartAt:         new(now.Format(time.RFC3339)),
		StopAt:          new(now.Format(time.RFC3339)),
		Scenario:        &scenario,
		ScenarioVersion: new("1"),
		ScenarioHash:    new(""),
		Message:         new(fmt.Sprintf("Repeat offense: tier %d, source alert %d", op.Tier+1, op.AlertID)),
		EventsCount:     new(int32(0)),
		Capacity:        new(int32(0)),
		Leakspeed:       new("0"),
		Simulated:       new(false),
		Events:          []*models.Event{},
		Source: &models.Source{
			Scope: new(types.Ip),
			Value: &op.IP,
		},
		Kind: Origin,
		Decisions: []*models.Decision{{
			Origin:   new(Origin),
			Type:     new(types.DecisionTypeBan),
			Scope:    new(types.Ip),
			Value:    &op.IP,
			Duration: new(duration.String()),
			Scenario: &scenario,
		}},
	}
	ids, _, err := c.api.Alerts.Add(ctx, models.AddAlertsRequest{a})
	if err == nil && (ids == nil || len(*ids) != 1) {
		return errors.New("LAPI did not acknowledge one escalation alert")
	}
	return err
}

func value[T any](v *T) (zero T) {
	if v != nil {
		return *v
	}
	return zero
}
