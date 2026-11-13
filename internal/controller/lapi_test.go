package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOfficialClientContract(t *testing.T) {
	const userAgent = "cs-escalation-controller/test"
	var writes int
	var submitted models.AddAlertsRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, userAgent, r.Header.Get("User-Agent"))
		switch r.URL.Path {
		case "/v1/heartbeat":
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
		case "/v1/watchers/login":
			json.NewEncoder(w).Encode(map[string]string{"token": "test-token", "expire": time.Now().Add(time.Hour).Format(time.RFC3339)})
		case "/v1/alerts":
			assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
			if r.Method == "GET" {
				assert.Equal(t, "0", r.URL.Query().Get("limit"))
				assert.Empty(t, r.URL.Query().Get("since"), "event-start filter can miss delayed alerts")
				assert.Equal(t, "crowdsec", r.URL.Query().Get("origin"))
				assert.Equal(t, "true", r.URL.Query().Get("has_active_decision"))
				assert.Equal(t, "ban", r.URL.Query().Get("decision_type"))
				assert.Equal(t, "false", r.URL.Query().Get("include_capi"))
				assert.Equal(t, "false", r.URL.Query().Get("simulated"))
				json.NewEncoder(w).Encode([]*models.Alert{testAlert(1, time.Now())})
				return
			}
			writes++
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&submitted))
			w.WriteHeader(http.StatusGatewayTimeout)
		case "/v1/allowlists/check/192.0.2.1":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected endpoint: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, "test", "test", userAgent)
	require.NoError(t, err)
	ctx := t.Context()
	require.NoError(t, c.Heartbeat(ctx))
	alerts, _, err := c.Alerts(ctx)
	require.NoError(t, err)
	assert.Len(t, alerts, 1)
	allowed, err := c.Allowlisted(ctx, "192.0.2.1")
	require.NoError(t, err)
	assert.False(t, allowed)
	now := time.Now().UTC()
	source := testAlert(42, now)
	source.ScenarioVersion = new("0.3")
	source.ScenarioHash = new("scenario-hash")
	source.MachineID = "detector"
	source.UUID = "source-uuid"
	source.Message = new("Ip 192.0.2.1 performed 'crowdsecurity/http-probing' (11 events).")
	source.Meta = models.Meta{
		{
			Key:   "target_uri",
			Value: `["/wp-login.php"]`,
		},
		{
			Key:   "method",
			Value: `["GET"]`,
		},
	}
	source.Source.IP = "192.0.2.1"
	source.Source.Scope = new("ip")
	source.Source.Value = new("::ffff:192.0.2.1")
	source.Source.Cn = "SE"
	source.Source.AsName = "Example AS"
	source.Source.AsNumber = "64500"
	source.Source.Range = "192.0.2.0/24"
	source.Source.Latitude = 59.3
	source.Source.Longitude = 18.1
	originalSource := *source.Source
	err = c.Ban(ctx, Operation{
		IP:                "192.0.2.1",
		AlertID:           42,
		Tier:              2,
		Until:             now.Add(12 * time.Hour),
		SourceDecisionIDs: []int64{123, 124},
		SourceBanUntil:    now.Add(4 * time.Hour),
	}, source, now)
	require.Error(t, err)
	assert.Equal(t, 1, writes, "ambiguous write retried")
	require.Len(t, submitted, 1)
	assert.Equal(t, Origin, submitted[0].Kind)
	expectedSource := originalSource
	expectedSource.Scope = new("Ip")
	expectedSource.Value = new("192.0.2.1")
	assert.Equal(t, &expectedSource, submitted[0].Source)
	assert.Equal(t, originalSource, *source.Source, "source alert must not be mutated")
	assert.Equal(t, source.Scenario, submitted[0].Scenario)
	assert.Equal(t, source.ScenarioVersion, submitted[0].ScenarioVersion)
	assert.Empty(t, value(submitted[0].ScenarioHash))
	assert.Equal(t, "Repeat offense: tier 3, source alert 42", value(submitted[0].Message))
	assert.Equal(t, models.Meta{
		{
			Key:   "escalation_tier",
			Value: "3",
		},
		{
			Key:   "source_alert_id",
			Value: "42",
		},
		{
			Key:   "escalation_until",
			Value: now.Add(12 * time.Hour).Format(time.RFC3339),
		},
		{
			Key:   "source_decision_ids",
			Value: "[123,124]",
		},
		{
			Key:   "source_ban_until",
			Value: now.Add(4 * time.Hour).Format(time.RFC3339),
		},
		{
			Key:   "escalation_added_duration",
			Value: "8h0m0s",
		},
		{
			Key:   "source_machine_id",
			Value: "detector",
		},
		{
			Key:   "source_alert_uuid",
			Value: "source-uuid",
		},
	}, submitted[0].Meta)
	assert.Empty(t, submitted[0].Events)
	assert.Zero(t, value(submitted[0].EventsCount))
	require.Len(t, submitted[0].Decisions, 1)
	assert.Equal(t, source.Scenario, submitted[0].Decisions[0].Scenario)
	assert.Equal(t, Origin, value(submitted[0].Decisions[0].Origin))
	assert.Equal(t, "12h0m0s", value(submitted[0].Decisions[0].Duration))
	// Operations persisted before provenance was introduced still submit safely.
	err = c.Ban(ctx, Operation{
		IP:      "192.0.2.1",
		AlertID: 42,
		Tier:    2,
		Until:   now.Add(12 * time.Hour),
	}, source, now)
	require.Error(t, err)
	assert.Equal(t, 2, writes)
	require.Len(t, submitted, 1)
	for _, meta := range submitted[0].Meta {
		assert.NotContains(t, []string{"source_ban_until", "source_decision_ids", "escalation_added_duration"}, meta.Key)
	}
}

func TestOfficialClientReauthenticates(t *testing.T) {
	logins := 0
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/watchers/login":
			logins++
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{
				"token":  "refreshed-token",
				"expire": time.Now().Add(time.Hour).Format(time.RFC3339),
			}))
		case "/v1/alerts":
			requests++
			if requests == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			assert.NoError(t, json.NewEncoder(w).Encode([]*models.Alert{}))
		default:
			t.Errorf("unexpected endpoint: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, "test", "test", "cs-escalation-controller/test")
	require.NoError(t, err)
	_, _, err = c.Alerts(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 2, logins)
	assert.Equal(t, 2, requests)
}

func TestAlertsBeyondFormerLimit(t *testing.T) {
	const count = 10001
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/watchers/login":
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{
				"token":  "test-token",
				"expire": time.Now().Add(time.Hour).Format(time.RFC3339),
			}))
		case "/v1/alerts":
			assert.Equal(t, "0", r.URL.Query().Get("limit"))
			alerts := make([]*models.Alert, count)
			for i := range alerts {
				alerts[i] = &models.Alert{ID: int64(i + 1)}
			}
			assert.NoError(t, json.NewEncoder(w).Encode(alerts))
		default:
			t.Errorf("unexpected endpoint: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, "test", "test", "cs-escalation-controller/test")
	require.NoError(t, err)
	alerts, _, err := c.Alerts(t.Context())
	require.NoError(t, err)
	require.Len(t, alerts, count)
	for i, alert := range alerts {
		assert.Equal(t, int64(i+1), alert.ID)
	}
}
