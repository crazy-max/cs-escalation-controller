//go:build integration

package integration

import (
	"testing"
	"time"

	"github.com/crazy-max/cs-escalation-controller/internal/controller"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamChanges(t *testing.T) {
	_, fixture := integrationClient(t)
	stream := integrationStream(t)
	ctx := t.Context()
	submitIntegrationAttack(t, fixture)
	changes, err := stream.Decisions(ctx, false)
	require.NoError(t, err)
	require.Len(t, changes.New, 2)
	for _, d := range changes.New {
		assert.Equal(t, types.CrowdSecOrigin, *d.Origin)
		assert.Equal(t, "192.0.2.1", *d.Value)
	}
	_, _, err = fixture.Decisions.Delete(ctx, apiclient.DecisionsDeleteOpts{IPEquals: "192.0.2.1"})
	require.NoError(t, err)
	changes, err = stream.Decisions(ctx, false)
	require.NoError(t, err)
	assert.Len(t, changes.Deleted, 2)
}

func TestStreamRejectsInvalidKey(t *testing.T) {
	stream, err := controller.NewStreamClient("http://crowdsec:8080", "invalid-bouncer-key", "cs-escalation-controller/test")
	require.NoError(t, err)
	_, err = stream.Decisions(t.Context(), true)
	var response *apiclient.ErrorResponse
	require.ErrorAs(t, err, &response)
	assert.NotEmpty(t, response.Message)
}

func TestStreamResync(t *testing.T) {
	_, fixture := integrationClient(t)
	stream := integrationStream(t)
	ctx := t.Context()
	submitIntegrationAttack(t, fixture)
	changes, err := stream.Decisions(ctx, false)
	require.NoError(t, err)
	require.Len(t, changes.New, 2)
	changes, err = stream.Decisions(ctx, false)
	require.NoError(t, err)
	assert.Empty(t, changes.New)
	changes, err = stream.Decisions(ctx, true)
	require.NoError(t, err)
	assert.Len(t, changes.New, 2)
}

func TestStreamIgnoresOwnBans(t *testing.T) {
	api, fixture := integrationClient(t)
	stream := integrationStream(t)
	now := time.Now().UTC()
	require.NoError(t, api.Ban(t.Context(), controller.Operation{
		IP:      "192.0.2.1",
		AlertID: 1,
		Tier:    1,
		Until:   now.Add(8 * time.Hour),
	}, now))
	require.Len(t, integrationEscalations(t, fixture), 1)
	changes, err := stream.Decisions(t.Context(), false)
	require.NoError(t, err)
	assert.Empty(t, changes.New)
}
