package controller

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
)

// DecisionStream uses a dedicated bouncer identity, separate from machine auth.
type DecisionStream interface {
	Decisions(context.Context, bool) (*models.DecisionsStreamResponse, error)
}

type StreamClient struct {
	api *apiclient.ApiClient
}

func NewStreamClient(address, apiKey, userAgent string) (*StreamClient, error) {
	if apiKey == "" {
		return nil, errors.New("lapi.bouncerAPIKey or lapi.bouncerAPIKeyFile is required for the decisions stream")
	}
	u, err := url.Parse(strings.TrimRight(address, "/") + "/")
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &apiclient.APIKeyTransport{
			APIKey: apiKey,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	api, err := apiclient.NewDefaultClient(u, "v1", userAgent, client)
	if err != nil {
		return nil, err
	}
	return &StreamClient{api: api}, nil
}

func (c *StreamClient) Decisions(ctx context.Context, startup bool) (*models.DecisionsStreamResponse, error) {
	decisions, _, err := c.api.Decisions.GetStream(ctx, apiclient.DecisionsStreamOpts{
		Startup: startup,
		Scopes:  types.Ip,
		Origins: types.CrowdSecOrigin,
	})
	return decisions, err
}
