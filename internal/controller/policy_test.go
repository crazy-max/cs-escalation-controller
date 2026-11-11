package controller

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExponentialCap(t *testing.T) {
	cases := []struct {
		name         string
		base         time.Duration
		multiplier   int64
		maximum      time.Duration
		previousTier int
		want         time.Duration
		wantTier     int
	}{
		{
			name:       "custom multiplier",
			base:       time.Hour,
			multiplier: 3,
			maximum:    10 * time.Hour,
			want:       3 * time.Hour,
			wantTier:   1,
		},
		{
			name:       "cap between powers",
			base:       4 * time.Hour,
			multiplier: 2,
			maximum:    6 * time.Hour,
			want:       6 * time.Hour,
			wantTier:   1,
		},
		{
			name:       "base equals cap",
			base:       time.Hour,
			multiplier: 2,
			maximum:    time.Hour,
			want:       time.Hour,
			wantTier:   0,
		},
		{
			name:       "multiplication would overflow",
			base:       time.Hour,
			multiplier: math.MaxInt64,
			maximum:    time.Duration(math.MaxInt64),
			want:       time.Duration(math.MaxInt64),
			wantTier:   1,
		},
		{
			name:         "stored tier above cap",
			base:         4 * time.Hour,
			multiplier:   2,
			maximum:      720 * time.Hour,
			previousTier: 20,
			want:         720 * time.Hour,
			wantTier:     8,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := Policy{
				BaseDuration: tc.base,
				Multiplier:   tc.multiplier,
				MaxDuration:  tc.maximum,
			}
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			previous := Episode{
				Tier:  tc.previousTier,
				Until: now,
			}
			ep, fresh := p.Next(previous, now, now, now, now)
			require.True(t, fresh)
			assert.Equal(t, tc.want, ep.Until.Sub(now))
			assert.Equal(t, tc.wantTier, ep.Tier)
		})
	}
}

func TestPolicy(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	p := Policy{
		BaseDuration: 4 * time.Hour,
		Multiplier:   2,
		MaxDuration:  720 * time.Hour,
		ResetAfter:   720 * time.Hour,
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
				Tier:       8,
				Until:      now,
				LastAttack: now.Add(-720 * time.Hour),
			},
			start:     now,
			wantTier:  8,
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

func TestExponentialAndResetConfiguration(t *testing.T) {
	p := Policy{
		BaseDuration: 4 * time.Hour,
		Multiplier:   2,
		MaxDuration:  720 * time.Hour,
		ResetAfter:   0,
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var ep Episode
	durations := []time.Duration{4, 8, 16, 32, 64, 128, 256, 512, 720, 720}
	for i, hours := range durations {
		var fresh bool
		ep, fresh = p.Next(ep, now, now, now, now.Add(time.Hour))
		require.True(t, fresh, "step %d", i)
		require.Equal(t, min(i, 8), ep.Tier)
		require.Equal(t, hours*time.Hour, ep.Until.Sub(now))
		now = ep.Until.Add(90 * 24 * time.Hour)
	}
	p.ResetAfter = 90 * 24 * time.Hour
	ep, _ = p.Next(ep, now, now, now, now.Add(time.Hour))
	assert.Zero(t, ep.Tier, "custom reset not applied")
}
