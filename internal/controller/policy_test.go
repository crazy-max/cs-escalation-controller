package controller

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicy(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	p := Policy{
		Durations:  []time.Duration{4 * time.Hour, 8 * time.Hour, 12 * time.Hour, 24 * time.Hour, 168 * time.Hour, 720 * time.Hour},
		ResetAfter: 720 * time.Hour,
	}
	cases := []struct {
		name      string
		previous  Episode
		start     time.Time
		wantTier  int
		wantFresh bool
	}{
		{
			name:      "first offense",
			start:     now,
			wantTier:  0,
			wantFresh: true,
		},
		{
			name: "another scenario in same episode",
			previous: Episode{
				Tier:  0,
				Until: now.Add(time.Hour),
			},
			start:     now,
			wantTier:  0,
			wantFresh: false,
		},
		{
			name: "attack at expiry escalates",
			previous: Episode{
				Tier:  0,
				Until: now,
			},
			start:     now,
			wantTier:  1,
			wantFresh: true,
		},
		{
			name: "late alert does not escalate",
			previous: Episode{
				Tier:       2,
				Until:      now.Add(-time.Hour),
				LastAttack: now.Add(-2 * time.Hour),
			},
			start:     now.Add(-3 * time.Hour),
			wantTier:  2,
			wantFresh: false,
		},
		{
			name: "reset after full quiet interval",
			previous: Episode{
				Tier:  3,
				Until: now.Add(-720 * time.Hour),
			},
			start:     now,
			wantTier:  0,
			wantFresh: true,
		},
		{
			name: "month ban does not reset itself",
			previous: Episode{
				Tier:       5,
				Until:      now,
				LastAttack: now.Add(-720 * time.Hour),
			},
			start:     now,
			wantTier:  5,
			wantFresh: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, fresh := p.Next(tc.previous, tc.start, now, now, now.Add(4*time.Hour))
			assert.Equal(t, tc.wantTier, got.Tier)
			assert.Equal(t, tc.wantFresh, fresh)
			assert.False(t, got.Until.Before(now.Add(4*time.Hour)), "shortened base ban")
		})
	}
}

func TestLadderAndResetConfiguration(t *testing.T) {
	p := Policy{
		Durations:  []time.Duration{4 * time.Hour, 8 * time.Hour, 12 * time.Hour, 24 * time.Hour, 168 * time.Hour, 720 * time.Hour},
		ResetAfter: 0,
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var ep Episode
	for i := range 8 {
		var fresh bool
		ep, fresh = p.Next(ep, now, now, now, now.Add(time.Hour))
		require.True(t, fresh, "step %d", i)
		require.Equal(t, min(i, 5), ep.Tier)
		require.Equal(t, p.Durations[min(i, 5)], ep.Until.Sub(now))
		now = ep.Until.Add(90 * 24 * time.Hour)
	}
	p.ResetAfter = 90 * 24 * time.Hour
	ep, _ = p.Next(ep, now, now, now, now.Add(time.Hour))
	assert.Zero(t, ep.Tier, "custom reset not applied")
}
