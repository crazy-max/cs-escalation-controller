package controller

import (
	"cmp"
	"context"
	stderrors "errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

// API is the boundary between policy/state and the upstream CrowdSec client.
type API interface {
	Heartbeat(context.Context) error
	Alerts(context.Context) ([]*models.Alert, time.Time, error)
	Alert(context.Context, int64) (*models.Alert, error)
	Allowlisted(context.Context, string) (bool, error)
	Ban(context.Context, Operation, time.Time) error
}

type Controller struct {
	API              API
	Stream           DecisionStream
	Store            *Store
	Policy           Policy
	ExcludeScenarios []string
	Log              zerolog.Logger
}

func (c *Controller) Reconcile(ctx context.Context) (resultErr error) {
	started := time.Now()
	c.Log.Debug().Msg("reconciliation started")
	defer func() {
		c.Log.Debug().Str("duration", time.Since(started).Round(time.Microsecond).String()).Err(resultErr).Msg("reconciliation finished")
	}()
	// Snapshot active local bans. LAPI's "since" filters event start, not
	// insertion time, and would silently miss long-running SSH scenarios.
	alerts, observed, err := c.API.Alerts(ctx)
	if err != nil {
		return err
	}
	c.Log.Debug().Int("alerts", len(alerts)).Msg("active ban alerts fetched")
	slices.SortStableFunc(alerts, func(a, b *models.Alert) int {
		if order := cmp.Compare(a.CreatedAt, b.CreatedAt); order != 0 {
			return order
		}
		return cmp.Compare(a.ID, b.ID)
	})

	var beforeStartup, seen, notQualifying, sameEpisode, offenses int
	err = c.Store.Update(func(s *State) error {
		present := make(map[int64]bool, len(alerts))
		for _, a := range alerts {
			present[a.ID] = true
			created, err := time.Parse(time.RFC3339Nano, a.CreatedAt)
			if err != nil {
				c.Log.Warn().Int64("alert_id", a.ID).Err(err).Msg("invalid alert creation time")
				continue
			}
			if created.Before(s.Started) {
				beforeStartup++
				continue
			}
			if _, alreadySeen := s.Seen[a.ID]; alreadySeen {
				seen++
				continue
			}
			ip, baseUntil, ok := c.qualifying(a, observed)
			if !ok {
				notQualifying++
				continue
			}
			start, err := time.Parse(time.RFC3339Nano, value(a.StartAt))
			if err != nil {
				c.Log.Warn().Int64("alert_id", a.ID).Err(err).Msg("invalid alert start time")
				continue
			}
			stop, err := time.Parse(time.RFC3339Nano, value(a.StopAt))
			if err != nil {
				c.Log.Warn().Int64("alert_id", a.ID).Err(err).Msg("invalid alert stop time")
				continue
			}
			if start.After(stop) || stop.After(observed.Add(time.Minute)) || created.After(observed.Add(time.Minute)) {
				c.Log.Warn().Int64("alert_id", a.ID).Msg("inconsistent or future alert timestamps")
				continue
			}
			s.Seen[a.ID] = created
			episode, fresh := c.Policy.Next(s.Episodes[ip], start, stop, created, baseUntil)
			s.Episodes[ip] = episode
			if !fresh {
				sameEpisode++
				continue
			}
			offenses++
			c.Log.Info().Str("ip", ip).Int("tier", episode.Tier+1).Time("until", episode.Until).Bool("dry_run", s.DryRun).Msg("offense")
			if !s.DryRun && episode.Until.After(baseUntil.Add(2*time.Second)) {
				s.Pending[a.ID] = Operation{
					IP:      ip,
					AlertID: a.ID,
					Tier:    episode.Tier,
					Until:   episode.Until,
				}
			}
		}
		// Persist processing before any API write. Forget IDs only when the
		// snapshot no longer contains them, after expiry or manual deletion.
		for id := range s.Seen {
			if !present[id] {
				delete(s.Seen, id)
			}
		}
		for id, op := range s.Pending {
			if !present[id] && !op.Attempted {
				delete(s.Pending, id)
			}
		}
		if c.Policy.ResetAfter > 0 {
			for ip, ep := range s.Episodes {
				quietSince := ep.Until
				if ep.LastAttack.After(quietSince) {
					quietSince = ep.LastAttack
				}
				if !observed.Before(quietSince.Add(c.Policy.ResetAfter)) {
					delete(s.Episodes, ip)
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	c.Log.Debug().
		Int("before_startup", beforeStartup).
		Int("already_seen", seen).
		Int("not_qualifying", notQualifying).
		Int("same_episode", sameEpisode).
		Int("new_offenses", offenses).
		Msg("alerts processed")
	state, err := c.Store.Read()
	if err != nil {
		return err
	}
	c.Log.Debug().Bool("dry_run", state.DryRun).Int("pending", len(state.Pending)).Msg("processing pending escalations")
	var failures []error
	for _, op := range state.Pending {
		if err := c.reconcileOperation(ctx, op); err != nil {
			failures = append(failures, err)
		}
	}
	return stderrors.Join(failures...)
}

func (c *Controller) qualifying(a *models.Alert, now time.Time) (string, time.Time, bool) {
	if value(a.Simulated) || a.Source == nil || !strings.EqualFold(value(a.Source.Scope), types.Ip) || slices.Contains(c.ExcludeScenarios, value(a.Scenario)) {
		return "", time.Time{}, false
	}
	ip, err := netip.ParseAddr(value(a.Source.Value))
	if err != nil {
		return "", time.Time{}, false
	}
	ip = ip.Unmap()
	var until time.Time
	for _, d := range a.Decisions {
		if !isLocalIPBan(d) {
			continue
		}
		dip, err := netip.ParseAddr(value(d.Value))
		if err != nil || dip.Unmap() != ip {
			continue
		}
		duration, err := time.ParseDuration(value(d.Duration))
		if err == nil && duration > 0 && now.Add(duration).After(until) {
			until = now.Add(duration)
		}
	}
	return ip.String(), until, !until.IsZero()
}

func (c *Controller) reconcileOperation(ctx context.Context, op Operation) error {
	now := time.Now().UTC()
	finish := func() error {
		return c.Store.Update(func(s *State) error { delete(s.Pending, op.AlertID); return nil })
	}
	if !now.Before(op.Until) {
		return finish()
	}
	if op.Attempted {
		c.Log.Warn().Int64("alert_id", op.AlertID).Time("until", op.Until).
			Msg("previous write outcome uncertain; not resubmitting")
		return nil
	}
	allowed, err := c.API.Allowlisted(ctx, op.IP)
	if err != nil {
		return err
	}
	if allowed {
		c.Log.Info().Str("ip", op.IP).Msg("escalation skipped: allowlisted")
		return finish()
	}
	// Check the source decision again: a deleted/expired ban is not restored.
	a, err := c.API.Alert(ctx, op.AlertID)
	if err != nil {
		return err
	}
	ip, _, ok := c.qualifying(a, time.Now().UTC())
	if !ok || ip != op.IP {
		return finish()
	}
	// A crash or timeout after POST cannot be distinguished from a deleted ban.
	// Journal before submission; never blindly replay that non-idempotent write.
	if err := c.Store.Update(func(s *State) error {
		op.Attempted = true
		s.Pending[op.AlertID] = op
		return nil
	}); err != nil {
		return err
	}
	if err := c.API.Ban(ctx, op, time.Now().UTC()); err != nil {
		return errors.Wrapf(err, "alert %d: write outcome uncertain", op.AlertID)
	}
	c.Log.Info().Str("ip", op.IP).Int("tier", op.Tier+1).Time("until", op.Until).Msg("ban extended")
	return finish()
}

func (c *Controller) relevantDecision(d *models.Decision) bool {
	return isLocalIPBan(d) && !slices.Contains(c.ExcludeScenarios, value(d.Scenario))
}

func isLocalIPBan(d *models.Decision) bool {
	return value(d.Origin) == types.CrowdSecOrigin && value(d.Type) == types.DecisionTypeBan && strings.EqualFold(value(d.Scope), types.Ip) && !value(d.Simulated)
}
