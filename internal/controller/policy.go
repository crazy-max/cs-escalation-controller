package controller

import "time"

// Policy counts ban episodes, rather than individual alerts or scenarios.
type Policy struct {
	Durations  []time.Duration
	ResetAfter time.Duration
}

type Episode struct {
	Tier       int       `json:"tier"`
	Until      time.Time `json:"until"`
	LastAttack time.Time `json:"last_attack"`
}

// Next groups alerts whose event interval starts before the current ban ends.
// Time spent banned is not quiet time. Late events never move clocks backwards.
func (p Policy) Next(previous Episode, start, stop, created, baseUntil time.Time) (Episode, bool) {
	if !previous.Until.IsZero() && start.Before(previous.Until) {
		if stop.After(previous.LastAttack) {
			previous.LastAttack = stop
		}
		if baseUntil.After(previous.Until) {
			previous.Until = baseUntil
		}
		return previous, false
	}
	tier := 0
	quietSince := previous.Until
	if previous.LastAttack.After(quietSince) {
		quietSince = previous.LastAttack
	}
	if !previous.Until.IsZero() && (p.ResetAfter == 0 || start.Sub(quietSince) < p.ResetAfter) {
		tier = min(previous.Tier+1, len(p.Durations)-1)
	}
	until := created.Add(p.Durations[tier])
	if baseUntil.After(until) {
		until = baseUntil
	}
	return Episode{
		Tier:       tier,
		Until:      until,
		LastAttack: stop,
	}, true
}
