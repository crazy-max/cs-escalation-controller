//go:build integration

package integration

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/crazy-max/cs-escalation-controller/internal/controller"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestControllerDryRun(t *testing.T) {
	api, fixture := integrationClient(t)
	c, _ := integrationRepeatOffense(t, api, true)
	submitIntegrationAttack(t, fixture)
	require.NoError(t, c.Reconcile(t.Context()))
	state, err := c.Store.Read()
	require.NoError(t, err)
	assert.Equal(t, 1, state.Episodes["192.0.2.1"].Tier)
	assert.Empty(t, integrationEscalations(t, fixture))
}

func TestControllerEscalationRestart(t *testing.T) {
	api, fixture := integrationClient(t)
	c, path := integrationRepeatOffense(t, api, false)
	submitIntegrationAttack(t, fixture)
	require.NoError(t, c.Reconcile(t.Context()))
	require.NoError(t, c.Store.Close())
	reopened, err := controller.OpenStore(path, "test", false, time.Now().UTC())
	require.NoError(t, err)
	t.Cleanup(func() { reopened.Close() })
	c.Store = reopened
	require.NoError(t, c.Reconcile(t.Context()))
	got := integrationEscalations(t, fixture)
	require.Len(t, got, 1)
	require.Len(t, got[0].Decisions, 1)
	d := got[0].Decisions[0]
	duration, err := time.ParseDuration(*d.Duration)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, duration, 7*time.Hour+59*time.Minute)
	assert.LessOrEqual(t, duration, 8*time.Hour)
	assert.Equal(t, controller.Origin, *d.Origin)
	assert.Equal(t, "192.0.2.1", *d.Value)
}

func TestControllerStart(t *testing.T) {
	api, fixture := integrationClient(t)
	c, _ := integrationRepeatOffense(t, api, false)
	c.Stream = integrationStream(t)
	ready := make(chan struct{})
	c.Log = zerolog.New(io.Discard).Hook(zerolog.HookFunc(func(_ *zerolog.Event, _ zerolog.Level, message string) {
		if message == "scheduler started" {
			close(ready)
		}
	}))
	ctx, cancel := context.WithCancelCause(t.Context())
	finished := make(chan struct{})
	var runErr error
	go func() {
		defer close(finished)
		runErr = c.Start(ctx, "@every 1s")
	}()
	t.Cleanup(func() {
		cancel(nil)
		select {
		case <-finished:
			assert.NoError(t, runErr)
		case <-time.After(5 * time.Second):
			t.Error("controller did not stop")
		}
	})
	// Publish only after startup reconciliation, so a stream delta must trigger it.
	select {
	case <-ready:
	case <-finished:
		t.Fatalf("controller stopped before startup: %v", runErr)
	case <-time.After(10 * time.Second):
		t.Fatal("controller did not start")
	}
	submitIntegrationAttack(t, fixture)
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		alerts, _, err := fixture.Alerts.List(ctx, apiclient.AlertsListOpts{
			OriginEquals:         controller.Origin,
			ActiveDecisionEquals: new(true),
			Limit:                new(0),
		})
		if assert.NoError(collect, err) {
			assert.Len(collect, *alerts, 1)
		}
	}, 10*time.Second, 100*time.Millisecond)
	cancel(nil)
	select {
	case <-finished:
		require.NoError(t, runErr)
	case <-time.After(5 * time.Second):
		t.Fatal("controller did not stop")
	}
	state, err := c.Store.Read()
	require.NoError(t, err)
	assert.Equal(t, 1, state.Episodes["192.0.2.1"].Tier)
	assert.Len(t, integrationEscalations(t, fixture), 1)
}
