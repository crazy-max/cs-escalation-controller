package controller

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type schedulerAPI struct {
	API
	list      func(context.Context) ([]*models.Alert, time.Time, error)
	heartbeat func(context.Context) error
}

func (a schedulerAPI) Heartbeat(ctx context.Context) error {
	if a.heartbeat != nil {
		return a.heartbeat(ctx)
	}
	return nil
}

func (a schedulerAPI) Alerts(ctx context.Context) ([]*models.Alert, time.Time, error) {
	return a.list(ctx)
}

func TestSchedulerRetriesOnSchedule(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var calls atomic.Int32
		c := Controller{
			API: schedulerAPI{
				list: func(context.Context) ([]*models.Alert, time.Time, error) {
					calls.Add(1)
					return nil, time.Time{}, errors.New("LAPI unavailable")
				},
			},
			Log: zerolog.Nop(),
		}
		done := make(chan error, 1)
		go func() { done <- c.Start(ctx, "@every 30s") }()
		synctest.Wait()
		assert.EqualValues(t, 1, calls.Load())
		time.Sleep(30 * time.Second)
		synctest.Wait()
		assert.EqualValues(t, 2, calls.Load())
		cancel()
		require.NoError(t, <-done)
		time.Sleep(time.Minute)
		assert.EqualValues(t, 2, calls.Load())
	})
}

func TestSchedulerSkipsOverlapAndWaitsForShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var calls atomic.Int32
		release := make(chan struct{})
		c := Controller{
			API: schedulerAPI{
				list: func(ctx context.Context) ([]*models.Alert, time.Time, error) {
					calls.Add(1)
					if calls.Load() > 1 {
						<-ctx.Done()
						<-release
					}
					return nil, time.Time{}, errors.New("LAPI unavailable")
				},
			},
			Log: zerolog.Nop(),
		}
		done := make(chan error, 1)
		go func() { done <- c.Start(ctx, "* * * * * *") }()
		synctest.Wait()
		time.Sleep(5 * time.Second)
		synctest.Wait()
		assert.EqualValues(t, 2, calls.Load())
		cancel()
		synctest.Wait()
		assert.Empty(t, done, "Start must wait for the active job")
		close(release)
		require.NoError(t, <-done)
	})
}

func TestSchedulerCanceledBeforeStartup(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c := Controller{Log: zerolog.Nop()}
	require.NoError(t, c.Start(ctx, "* * * * * *"))
}

func TestSchedulerRejectsInvalidScheduleBeforeReconcile(t *testing.T) {
	c := Controller{Log: zerolog.Nop()}
	for _, schedule := range []string{"invalid", "CRON_TZ=UTC", "TZ="} {
		t.Run(schedule, func(t *testing.T) {
			require.ErrorContains(t, c.Start(t.Context(), schedule), "invalid schedule")
		})
	}
}

func TestHeartbeatContinuesDuringReconcileAndWaitsForShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var heartbeats atomic.Int32
		var queries atomic.Int32
		release := make(chan struct{})
		c := Controller{
			API: schedulerAPI{
				heartbeat: func(ctx context.Context) error {
					if heartbeats.Add(1) == 1 {
						return errors.New("LAPI unavailable")
					}
					<-ctx.Done()
					<-release
					return ctx.Err()
				},
				list: func(ctx context.Context) ([]*models.Alert, time.Time, error) {
					queries.Add(1)
					<-ctx.Done()
					return nil, time.Time{}, ctx.Err()
				},
			},
			Log: zerolog.Nop(),
		}
		done := make(chan error, 1)
		go func() { done <- c.Start(ctx, "@every 1h") }()
		synctest.Wait()
		assert.EqualValues(t, 1, heartbeats.Load())
		assert.EqualValues(t, 1, queries.Load(), "heartbeat failure must not prevent reconciliation")

		time.Sleep(time.Minute)
		synctest.Wait()
		assert.EqualValues(t, 2, heartbeats.Load(), "heartbeat must retry during a blocked reconciliation")
		time.Sleep(time.Minute)
		synctest.Wait()
		assert.EqualValues(t, 2, heartbeats.Load(), "heartbeats must not overlap")

		cancel()
		synctest.Wait()
		assert.Empty(t, done, "shutdown must wait for the active heartbeat")
		close(release)
		require.NoError(t, <-done)
		time.Sleep(time.Minute)
		assert.EqualValues(t, 2, heartbeats.Load(), "heartbeats must stop on shutdown")
	})
}
