package controller

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/crazy-max/cron/v3"
	"github.com/crazy-max/cs-escalation-controller/internal/config"
)

// Start reconciles immediately, then on a schedule until ctx is canceled.
// It sends heartbeats independently every minute and waits for active jobs
// to finish before returning.
func (c *Controller) Start(ctx context.Context, schedule string) error {
	parsed, err := config.ParseSchedule(schedule)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return nil
	}
	var heartbeating atomic.Bool
	heartbeat := cron.FuncJob(func() {
		if ctx.Err() != nil || !heartbeating.CompareAndSwap(false, true) {
			return
		}
		defer heartbeating.Store(false)
		if err := c.API.Heartbeat(ctx); err != nil {
			if ctx.Err() == nil {
				c.Log.Error().Err(err).Msg("heartbeat failed")
			}
			return
		}
		c.Log.Debug().Msg("heartbeat sent")
	})
	var running atomic.Bool
	job := cron.FuncJob(func() {
		if ctx.Err() != nil {
			return
		}
		if !running.CompareAndSwap(false, true) {
			c.Log.Warn().Msg("skipping reconciliation: already running")
			return
		}
		defer running.Store(false)
		if err := c.Reconcile(ctx); err != nil && ctx.Err() == nil {
			c.Log.Error().Err(err).Msg("reconcile failed")
		}
	})
	scheduler := cron.New()
	jobID := scheduler.Schedule(parsed, job)
	scheduler.Schedule(cron.Every(time.Minute), heartbeat)
	heartbeat.Run()
	if ctx.Err() != nil {
		return nil
	}
	scheduler.Start()
	defer func() { <-scheduler.Stop().Done() }()
	job.Run()
	c.Log.Info().Str("schedule", schedule).Time("next_run", scheduler.Entry(jobID).Next).Msg("scheduler started")
	<-ctx.Done()
	return nil
}
