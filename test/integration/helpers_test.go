//go:build integration

package integration

import (
	"context"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/crazy-max/cs-escalation-controller/internal/controller"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/go-openapi/strfmt"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests run serially against the disposable LAPI in test/compose.yaml.
// Each test removes its decisions, including after a failed assertion.
func integrationClient(t *testing.T) (*controller.Client, *apiclient.ApiClient) {
	t.Helper()
	api, err := controller.NewClient("http://crowdsec:8080", "integration", "integration-password", "cs-escalation-controller/test")
	require.NoError(t, err)
	address, err := url.Parse("http://crowdsec:8080/")
	require.NoError(t, err)
	fixture := apiclient.NewClient(&apiclient.Config{
		URL:           address,
		MachineID:     "integration",
		Password:      strfmt.Password("integration-password"),
		VersionPrefix: "v1",
		UserAgent:     "cs-escalation-controller/test",
	})
	fixture.GetClient().Timeout = 30 * time.Second
	t.Cleanup(func() {
		_, _, err := fixture.Decisions.Delete(context.WithoutCancel(t.Context()), apiclient.DecisionsDeleteOpts{IPEquals: "192.0.2.1"})
		assert.NoError(t, err)
	})
	return api, fixture
}

func integrationStream(t *testing.T) *controller.StreamClient {
	t.Helper()
	stream, err := controller.NewStreamClient("http://crowdsec:8080", "integration-bouncer-key", "cs-escalation-controller/test")
	require.NoError(t, err)
	changes, err := stream.Decisions(t.Context(), true)
	require.NoError(t, err)
	require.Empty(t, changes.New)
	return stream
}

func submitIntegrationAttack(t *testing.T, fixture *apiclient.ApiClient) {
	t.Helper()
	// LAPI's profiles create the base bans for two scenarios from one attack.
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	a := &models.Alert{
		StartAt:         new(now),
		StopAt:          new(now),
		Kind:            types.CrowdSecOrigin,
		Scenario:        new("integration/first-scenario"),
		Events:          []*models.Event{},
		EventsCount:     new(int32(0)),
		Capacity:        new(int32(0)),
		ScenarioHash:    new("test"),
		ScenarioVersion: new("1"),
		Message:         new("integration"),
		Leakspeed:       new("0"),
		Simulated:       new(false),
		Remediation:     true,
		Source: &models.Source{
			Scope: new(types.Ip),
			Value: new("192.0.2.1"),
		},
	}
	b := *a
	b.Scenario = new("integration/second-scenario")
	_, _, err := fixture.Alerts.Add(t.Context(), models.AddAlertsRequest{a, &b})
	require.NoError(t, err)
}

func integrationRepeatOffense(t *testing.T, api *controller.Client, dryRun bool) (*controller.Controller, string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := controller.OpenStore(path, "test", dryRun, now.Add(-time.Minute))
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	c := &controller.Controller{
		API:   api,
		Store: store,
		Policy: controller.Policy{
			Durations:  []time.Duration{4 * time.Hour, 8 * time.Hour, 12 * time.Hour},
			ResetAfter: 720 * time.Hour,
		},
		Log: zerolog.Nop(),
	}
	require.NoError(t, c.Store.Update(func(s *controller.State) error {
		s.Started = now.Add(-time.Minute)
		s.Episodes["192.0.2.1"] = controller.Episode{
			Tier:  0,
			Until: now.Add(-time.Minute),
		}
		return nil
	}))
	return c, path
}

func integrationEscalations(t *testing.T, fixture *apiclient.ApiClient) []*models.Alert {
	t.Helper()
	got, _, err := fixture.Alerts.List(t.Context(), apiclient.AlertsListOpts{
		OriginEquals:         controller.Origin,
		ActiveDecisionEquals: new(true),
		Limit:                new(0),
	})
	require.NoError(t, err)
	return *got
}
