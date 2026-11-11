package controller

import (
	"context"
	"slices"
	"sync/atomic"
	"time"

	"github.com/crazy-max/cron/v3"
	"github.com/crazy-max/cs-escalation-controller/internal/config"
	"github.com/pkg/errors"
)

// Start synchronizes active alerts, then checks decision changes on a schedule.
// It sends heartbeats independently every minute and waits for active jobs
// to finish before returning.
func (c *Controller) Start(ctx context.Context, schedule string) error {
	parsed, err := config.ParseSchedule(schedule)
	if err != nil {
		return err
	}
	if context.Cause(ctx) != nil {
		return nil
	}
	if c.Stream == nil {
		return errors.New("decisions stream is required")
	}
	var heartbeating atomic.Bool
	heartbeat := cron.FuncJob(func() {
		if context.Cause(ctx) != nil || !heartbeating.CompareAndSwap(false, true) {
			return
		}
		defer heartbeating.Store(false)
		if err := c.API.Heartbeat(ctx); err != nil {
			if context.Cause(ctx) == nil {
				c.Log.Error().Err(err).Msg("heartbeat failed")
			}
			return
		}
		c.Log.Debug().Msg("heartbeat sent")
	})
	var running atomic.Bool
	// Only the non-overlapping job accesses resync. A failed stream response
	// may have advanced LAPI's cursor, so recover with a fresh snapshot.
	resync := true
	job := cron.FuncJob(func() {
		if context.Cause(ctx) != nil {
			return
		}
		if !running.CompareAndSwap(false, true) {
			c.Log.Warn().Msg("skipping reconciliation: already running")
			return
		}
		defer running.Store(false)
		changes, err := c.Stream.Decisions(ctx, resync)
		if err != nil {
			resync = true
			if context.Cause(ctx) == nil {
				c.Log.Error().Err(err).Msg("decisions stream failed")
			}
			return
		}
		c.Log.Debug().Bool("resync", resync).Int("new", len(changes.New)).Int("deleted", len(changes.Deleted)).Msg("decision changes fetched")
		if !resync && !slices.ContainsFunc(changes.New, c.relevantDecision) && !slices.ContainsFunc(changes.Deleted, c.relevantDecision) {
			c.Log.Debug().Msg("no relevant decision changes")
			return
		}
		if err := c.Reconcile(ctx); err != nil {
			resync = true
			if context.Cause(ctx) == nil {
				c.Log.Error().Err(err).Msg("reconcile failed")
			}
			return
		}
		resync = false
	})
	scheduler := cron.New()
	jobID := scheduler.Schedule(parsed, job)
	scheduler.Schedule(cron.Every(time.Minute), heartbeat)
	heartbeat.Run()
	if context.Cause(ctx) != nil {
		return nil
	}
	scheduler.Start()
	defer func() { <-scheduler.Stop().Done() }()
	job.Run()
	c.Log.Info().Str("schedule", schedule).Time("next_run", scheduler.Entry(jobID).Next).Msg("scheduler started")
	<-ctx.Done()
	return nil
}
