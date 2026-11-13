package controller

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReconcileDebugLogs(t *testing.T) {
	c, f, _ := setup(t, true)
	var output bytes.Buffer
	c.Log = zerolog.New(&output).Level(zerolog.DebugLevel)
	c.ExcludeScenarios = []string{"excluded"}
	f.alerts = []*models.Alert{
		testAlert(1, f.observed.Add(-time.Hour)),
		testAlert(2, f.observed),
		testAlert(3, f.observed),
		testAlert(4, f.observed),
	}
	f.alerts[3].Scenario = new("excluded")
	require.NoError(t, c.Reconcile(t.Context()))
	assert.Contains(t, output.String(), `"alerts":4`)
	assert.Contains(t, output.String(), `"before_startup":1,"already_seen":0,"not_qualifying":1,"same_episode":1,"new_offenses":1`)
	assert.Contains(t, output.String(), `"dry_run":true,"pending":0`)
	assert.Contains(t, output.String(), `"message":"reconciliation finished"`)
	assert.Regexp(t, `"duration":"[0-9.]+(µs|ms|s)"`, output.String())

	output.Reset()
	require.NoError(t, c.Reconcile(t.Context()))
	assert.Contains(t, output.String(), `"already_seen":2`)
	assert.Contains(t, output.String(), `"new_offenses":0`)

	output.Reset()
	c.Log = c.Log.Level(zerolog.InfoLevel)
	require.NoError(t, c.Reconcile(t.Context()))
	assert.Empty(t, output.String(), "idle polling should be quiet at info level")
}

func TestReplayAndMultipleScenarios(t *testing.T) {
	c, f, path := setup(t, false)
	now := f.observed
	f.alerts = []*models.Alert{testAlert(1, now), testAlert(2, now)}
	f.alerts[1].Scenario = new("crowdsecurity/http-sensitive-files")
	for range 2 {
		require.NoError(t, c.Reconcile(t.Context()))
	}
	s, err := c.Store.Read()
	require.NoError(t, err)
	assert.Empty(t, f.bans)
	assert.Zero(t, s.Episodes["192.0.2.1"].Tier)
	require.NoError(t, c.Store.Close())
	reopened, err := OpenStore(path, "test", false, now)
	require.NoError(t, err)
	defer reopened.Close()
	c.Store = reopened
	require.NoError(t, c.Reconcile(t.Context()))
	s, err = c.Store.Read()
	require.NoError(t, err)
	assert.Zero(t, s.Episodes["192.0.2.1"].Tier, "restart counted duplicate")
}

func TestOperationSafety(t *testing.T) {
	cases := []struct {
		name       string
		dry        bool
		allowed    bool
		allowErr   error
		banErr     error
		deleted    bool
		wantWrites int
		wantError  bool
	}{
		{
			name:       "extend repeat offense",
			wantWrites: 1,
		},
		{
			name:       "dry run",
			dry:        true,
			wantWrites: 0,
		},
		{
			name:       "allowlist",
			allowed:    true,
			wantWrites: 0,
		},
		{
			name:       "allowlist unavailable",
			allowErr:   errors.New("unavailable"),
			wantError:  true,
			wantWrites: 0,
		},
		{
			name:       "manual unban before write",
			deleted:    true,
			wantWrites: 0,
		},
		{
			name:       "ambiguous write is never repeated",
			banErr:     errors.New("response lost"),
			wantError:  true,
			wantWrites: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, f, _ := setup(t, tc.dry)
			require.NoError(t, c.Store.Update(func(s *State) error {
				s.Episodes["192.0.2.1"] = Episode{
					Tier:  0,
					Until: f.observed.Add(-time.Minute),
				}
				return nil
			}))
			f.alerts = []*models.Alert{testAlert(3, f.observed), testAlert(4, f.observed)}
			f.fresh = testAlert(3, f.observed)
			if tc.deleted {
				f.fresh.Decisions = nil
			}
			f.allowed, f.allowErr, f.banErr = tc.allowed, tc.allowErr, tc.banErr
			for attempt := range 2 {
				err := c.Reconcile(t.Context())
				if tc.wantError && (tc.banErr == nil || attempt == 0) {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
			}
			assert.Len(t, f.bans, tc.wantWrites)
			s, err := c.Store.Read()
			require.NoError(t, err)
			assert.Equal(t, 1, s.Episodes["192.0.2.1"].Tier, "must advance exactly one tier")
			if len(f.bans) > 0 {
				assert.Equal(t, 8*time.Hour, f.bans[0].Until.Sub(f.observed))
			}
		})
	}
}

func TestInvalidAlertDoesNotBlockOthers(t *testing.T) {
	c, f, _ := setup(t, true)
	future := testAlert(1, f.observed.Add(2*time.Minute))
	f.alerts = []*models.Alert{future, testAlert(2, f.observed)}
	require.NoError(t, c.Reconcile(t.Context()))
	s, err := c.Store.Read()
	require.NoError(t, err)
	assert.Contains(t, s.Seen, int64(2))
	assert.NotContains(t, s.Seen, int64(1))
}

func TestLocalBanKinds(t *testing.T) {
	c, f, _ := setup(t, true)
	for _, kind := range []string{"crowdsec", "waf", ""} {
		t.Run(kind, func(t *testing.T) {
			a := testAlert(1, f.observed)
			a.Kind = kind
			_, _, _, ok := c.qualifying(a, f.observed)
			assert.True(t, ok)
		})
	}
}

func TestOnlyLocalIPBansQualify(t *testing.T) {
	c, _, _ := setup(t, true)
	cases := []struct {
		name   string
		change func(*models.Alert)
	}{
		{
			name:   "postfix alert only",
			change: func(a *models.Alert) { a.Decisions = nil },
		},
		{
			name:   "manual ban",
			change: func(a *models.Alert) { a.Decisions[0].Origin = new("cscli") },
		},
		{
			name:   "community ban",
			change: func(a *models.Alert) { a.Decisions[0].Origin = new("CAPI") },
		},
		{
			name:   "own ban",
			change: func(a *models.Alert) { a.Decisions[0].Origin = new(Origin) },
		},
		{
			name:   "simulation",
			change: func(a *models.Alert) { a.Simulated = new(true) },
		},
		{
			name:   "expired",
			change: func(a *models.Alert) { a.Decisions[0].Duration = new("-1s") },
		},
		{
			name:   "captcha",
			change: func(a *models.Alert) { a.Decisions[0].Type = new("captcha") },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := testAlert(1, time.Now())
			tc.change(a)
			_, _, _, ok := c.qualifying(a, time.Now())
			assert.False(t, ok, "unexpectedly qualified")
		})
	}
}

func TestDatabaseModeAndLock(t *testing.T) {
	c, _, path := setup(t, true)
	other, err := OpenStore(path, "test", true, time.Now())
	if other != nil {
		t.Cleanup(func() { other.Close() })
	}
	require.Error(t, err, "two writers allowed")
	require.NoError(t, c.Store.Close())
	other, err = OpenStore(path, "test", false, time.Now())
	if other != nil {
		t.Cleanup(func() { other.Close() })
	}
	require.Error(t, err, "dry-run state reused for enforcement")
}

func TestPendingSourceRemoved(t *testing.T) {
	c, f, _ := setup(t, false)
	require.NoError(t, c.Store.Update(func(s *State) error {
		s.Pending[42] = Operation{
			IP:      "192.0.2.1",
			AlertID: 42,
			Until:   f.observed.Add(time.Hour),
		}
		return nil
	}))
	require.NoError(t, c.Reconcile(t.Context()))
	s, err := c.Store.Read()
	require.NoError(t, err)
	assert.Empty(t, s.Pending)
	assert.Empty(t, f.bans)
}

func TestAlertsBeforeStartupAreIgnored(t *testing.T) {
	c, f, _ := setup(t, false)
	f.alerts = []*models.Alert{testAlert(1, f.observed.Add(-time.Hour))}
	require.NoError(t, c.Reconcile(t.Context()))
	s, err := c.Store.Read()
	require.NoError(t, err)
	assert.Empty(t, s.Episodes)
	assert.Empty(t, f.bans)
}

func TestLongerBaseBanIsPreserved(t *testing.T) {
	c, f, _ := setup(t, false)
	f.alerts = []*models.Alert{testAlert(1, f.observed)}
	f.alerts[0].Decisions[0].Duration = new("48h")
	require.NoError(t, c.Reconcile(t.Context()))
	s, err := c.Store.Read()
	require.NoError(t, err)
	assert.Equal(t, f.observed.Add(48*time.Hour), s.Episodes["192.0.2.1"].Until)
	assert.Empty(t, f.bans)
}

func TestExcludedScenario(t *testing.T) {
	c, f, _ := setup(t, false)
	c.ExcludeScenarios = []string{"crowdsecurity/http-probing"}
	f.alerts = []*models.Alert{testAlert(1, f.observed)}
	require.NoError(t, c.Reconcile(t.Context()))
	s, err := c.Store.Read()
	require.NoError(t, err)
	assert.Empty(t, s.Episodes)
	assert.Empty(t, f.bans)
}

func TestQuietHistoryIsPruned(t *testing.T) {
	c, f, _ := setup(t, false)
	require.NoError(t, c.Store.Update(func(s *State) error {
		s.Episodes["192.0.2.1"] = Episode{
			Tier:  2,
			Until: f.observed.Add(-c.Policy.ResetAfter),
		}
		s.Episodes["192.0.2.2"] = Episode{
			Tier:  2,
			Until: f.observed.Add(-c.Policy.ResetAfter + time.Second),
		}
		return nil
	}))
	require.NoError(t, c.Reconcile(t.Context()))
	s, err := c.Store.Read()
	require.NoError(t, err)
	assert.NotContains(t, s.Episodes, "192.0.2.1")
	assert.Contains(t, s.Episodes, "192.0.2.2")
}

func TestAmbiguousWriteIsNotRepeatedAfterRestart(t *testing.T) {
	c, f, path := setup(t, false)
	require.NoError(t, c.Store.Update(func(s *State) error {
		s.Episodes["192.0.2.1"] = Episode{
			Tier:  0,
			Until: f.observed.Add(-time.Minute),
		}
		return nil
	}))
	f.alerts = []*models.Alert{testAlert(1, f.observed)}
	f.fresh = f.alerts[0]
	f.banErr = errors.New("response lost")
	require.ErrorIs(t, c.Reconcile(t.Context()), f.banErr)
	require.Len(t, f.bans, 1)
	require.NoError(t, c.Store.Close())
	reopened, err := OpenStore(path, "test", false, f.observed)
	require.NoError(t, err)
	defer reopened.Close()
	c.Store = reopened
	f.banErr = nil
	require.NoError(t, c.Reconcile(t.Context()))
	assert.Len(t, f.bans, 1)
	s, err := c.Store.Read()
	require.NoError(t, err)
	assert.True(t, s.Pending[1].Attempted)
}

func TestPendingProvenanceSurvivesRestart(t *testing.T) {
	c, f, path := setup(t, false)
	require.NoError(t, c.Store.Update(func(s *State) error {
		s.Episodes["192.0.2.1"] = Episode{Until: f.observed.Add(-time.Minute)}
		return nil
	}))
	a := testAlert(42, f.observed)
	a.Decisions[0].ID = 100
	for _, tc := range []struct {
		id     int64
		change func(*models.Decision)
	}{
		{
			id:     101,
			change: func(d *models.Decision) { d.Duration = new("2h") },
		},
		{
			id:     102,
			change: func(d *models.Decision) { d.Value = new("192.0.2.2") },
		},
		{
			id:     103,
			change: func(d *models.Decision) { d.Origin = new(Origin) },
		},
		{
			id:     104,
			change: func(d *models.Decision) { d.Type = new("captcha") },
		},
		{
			id:     105,
			change: func(d *models.Decision) { d.Duration = new("-1s") },
		},
		{
			id:     106,
			change: func(d *models.Decision) { d.Duration = new("invalid") },
		},
	} {
		d := *a.Decisions[0]
		d.ID = tc.id
		tc.change(&d)
		a.Decisions = append(a.Decisions, &d)
	}
	f.alerts = []*models.Alert{a}
	f.allowErr = errors.New("temporarily unavailable")
	require.ErrorIs(t, c.Reconcile(t.Context()), f.allowErr)
	require.NoError(t, c.Store.Close())
	reopened, err := OpenStore(path, "test", false, f.observed)
	require.NoError(t, err)
	defer reopened.Close()
	c.Store = reopened
	f.allowErr = nil
	f.fresh = testAlert(42, f.observed)
	f.fresh.Decisions[0].Duration = new("3h")
	require.NoError(t, c.Reconcile(t.Context()))
	require.Len(t, f.bans, 1)
	assert.Equal(t, []int64{100, 101}, f.bans[0].SourceDecisionIDs)
	assert.Equal(t, f.observed.Add(4*time.Hour), f.bans[0].SourceBanUntil)
}

type fakeAPI struct {
	alerts   []*models.Alert
	observed time.Time
	allowed  bool
	allowErr error
	banErr   error
	getErr   error
	fresh    *models.Alert
	bans     []Operation
}

func (f *fakeAPI) Heartbeat(context.Context) error {
	return nil
}

func (f *fakeAPI) Alerts(context.Context) ([]*models.Alert, time.Time, error) {
	return f.alerts, f.observed, nil
}

func (f *fakeAPI) Alert(context.Context, int64) (*models.Alert, error) {
	return f.fresh, f.getErr
}

func (f *fakeAPI) Allowlisted(context.Context, string) (bool, error) {
	return f.allowed, f.allowErr
}

func (f *fakeAPI) Ban(_ context.Context, op Operation, _ *models.Alert, _ time.Time) error {
	f.bans = append(f.bans, op)
	return f.banErr
}

func testAlert(id int64, at time.Time) *models.Alert {
	return &models.Alert{
		ID:        id,
		CreatedAt: at.Format(time.RFC3339Nano),
		StartAt:   new(at.Format(time.RFC3339Nano)),
		StopAt:    new(at.Format(time.RFC3339Nano)),
		Kind:      "crowdsec",
		Scenario:  new("crowdsecurity/http-probing"),
		Source: &models.Source{
			Scope: new("Ip"),
			Value: new("192.0.2.1"),
		},
		Decisions: []*models.Decision{{
			Origin:   new("crowdsec"),
			Type:     new("ban"),
			Scope:    new("Ip"),
			Value:    new("192.0.2.1"),
			Duration: new("4h"),
		}},
	}
}

func setup(t *testing.T, dry bool) (*Controller, *fakeAPI, string) {
	t.Helper()
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenStore(path, "test", dry, now.Add(-time.Minute))
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })
	f := &fakeAPI{
		observed: now,
	}
	c := &Controller{
		Store: s,
		API:   f,
		Policy: Policy{
			BaseDuration: 4 * time.Hour,
			Multiplier:   2,
			MaxDuration:  720 * time.Hour,
			ResetAfter:   720 * time.Hour,
		},
		Log: zerolog.Nop(),
	}
	return c, f, path
}
