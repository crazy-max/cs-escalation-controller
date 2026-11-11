//go:build integration

package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLAPIHeartbeat(t *testing.T) {
	api, _ := integrationClient(t)
	require.NoError(t, api.Heartbeat(t.Context()))
}

func TestLAPIAllowlist(t *testing.T) {
	api, _ := integrationClient(t)
	allowed, err := api.Allowlisted(t.Context(), "192.0.2.99")
	require.NoError(t, err)
	assert.True(t, allowed)
	allowed, err = api.Allowlisted(t.Context(), "192.0.2.1")
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestLAPIAlerts(t *testing.T) {
	api, fixture := integrationClient(t)
	ctx := t.Context()
	submitIntegrationAttack(t, fixture)
	alerts, _, err := api.Alerts(ctx)
	require.NoError(t, err)
	require.Len(t, alerts, 2)
	alert, err := api.Alert(ctx, alerts[0].ID)
	require.NoError(t, err)
	assert.Equal(t, alerts[0].ID, alert.ID)
}
