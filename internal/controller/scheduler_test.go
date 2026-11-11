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

type streamFunc func(context.Context, bool) (*models.DecisionsStreamResponse, error)

func (f streamFunc) Decisions(ctx context.Context, startup bool) (*models.DecisionsStreamResponse, error) {
	return f(ctx, startup)
}

func emptyStream(context.Context, bool) (*models.DecisionsStreamResponse, error) {
	return &models.DecisionsStreamResponse{}, nil
}

func TestStreamTriggersAndRecovery(t *testing.T) {
	c, _, _ := setup(t, true)
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancelCause(t.Context())
		defer cancel(nil)
		var queries atomic.Int32
		var pulls atomic.Int32
		local := testAlert(1, time.Now()).Decisions[0]
		own := *local
		own.Origin = new(Origin)
		c.API = schedulerAPI{
			list: func(context.Context) ([]*models.Alert, time.Time, error) {
				if queries.Add(1) == 5 {
					return nil, time.Time{}, errors.New("alert query failed")
				}
				return nil, time.Now(), nil
			},
		}
		c.Stream = streamFunc(func(_ context.Context, startup bool) (*models.DecisionsStreamResponse, error) {
			n := pulls.Add(1)
			assert.Equal(t, n == 1 || n == 7 || n == 9, startup)
			switch n {
			case 3:
				return &models.DecisionsStreamResponse{New: []*models.Decision{&own}}, nil
			case 4, 8:
				return &models.DecisionsStreamResponse{New: []*models.Decision{local, local}}, nil
			case 5:
				return &models.DecisionsStreamResponse{Deleted: []*models.Decision{local}}, nil
			case 6:
				return nil, errors.New("stream response lost")
			default:
				return &models.DecisionsStreamResponse{}, nil
			}
		})
		done := make(chan error, 1)
		go func() { done <- c.Start(ctx, "@every 30s") }()
		synctest.Wait()
		assert.EqualValues(t, 1, queries.Load(), "startup must synchronize even with an empty stream")
		for _, want := range []int32{1, 1, 2, 3, 3, 4, 5, 6} {
			time.Sleep(30 * time.Second)
			synctest.Wait()
			assert.Equal(t, want, queries.Load())
		}
		cancel(nil)
		require.NoError(t, <-done)
	})
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
		ctx, cancel := context.WithCancelCause(t.Context())
		defer cancel(nil)
		var calls atomic.Int32
		c := Controller{
			API: schedulerAPI{
				list: func(context.Context) ([]*models.Alert, time.Time, error) {
					calls.Add(1)
					return nil, time.Time{}, errors.New("LAPI unavailable")
				},
			},
			Stream: streamFunc(emptyStream),
			Log:    zerolog.Nop(),
		}
		done := make(chan error, 1)
		go func() { done <- c.Start(ctx, "@every 30s") }()
		synctest.Wait()
		assert.EqualValues(t, 1, calls.Load())
		time.Sleep(30 * time.Second)
		synctest.Wait()
		assert.EqualValues(t, 2, calls.Load())
		cancel(nil)
		require.NoError(t, <-done)
		time.Sleep(time.Minute)
		assert.EqualValues(t, 2, calls.Load())
	})
}

func TestSchedulerSkipsOverlapAndWaitsForShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancelCause(t.Context())
		defer cancel(nil)
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
			Stream: streamFunc(emptyStream),
			Log:    zerolog.Nop(),
		}
		done := make(chan error, 1)
		go func() { done <- c.Start(ctx, "* * * * * *") }()
		synctest.Wait()
		time.Sleep(5 * time.Second)
		synctest.Wait()
		assert.EqualValues(t, 2, calls.Load())
		cancel(nil)
		synctest.Wait()
		assert.Empty(t, done, "Start must wait for the active job")
		close(release)
		require.NoError(t, <-done)
	})
}

func TestSchedulerCanceledBeforeStartup(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(nil)
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
		ctx, cancel := context.WithCancelCause(t.Context())
		defer cancel(nil)
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
					return context.Cause(ctx)
				},
				list: func(ctx context.Context) ([]*models.Alert, time.Time, error) {
					queries.Add(1)
					<-ctx.Done()
					return nil, time.Time{}, context.Cause(ctx)
				},
			},
			Stream: streamFunc(emptyStream),
			Log:    zerolog.Nop(),
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

		cancel(nil)
		synctest.Wait()
		assert.Empty(t, done, "shutdown must wait for the active heartbeat")
		close(release)
		require.NoError(t, <-done)
		time.Sleep(time.Minute)
		assert.EqualValues(t, 2, heartbeats.Load(), "heartbeats must stop on shutdown")
	})
}
