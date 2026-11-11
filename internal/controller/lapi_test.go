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
	err = c.Ban(ctx, Operation{
		IP:      "192.0.2.1",
		AlertID: 42,
		Tier:    2,
		Until:   now.Add(12 * time.Hour),
	}, now)
	require.Error(t, err)
	assert.Equal(t, 1, writes, "ambiguous write retried")
	require.Len(t, submitted, 1)
	assert.Equal(t, Origin, submitted[0].Kind)
	require.Len(t, submitted[0].Decisions, 1)
	assert.Equal(t, Origin, value(submitted[0].Decisions[0].Origin))
	assert.Equal(t, "12h0m0s", value(submitted[0].Decisions[0].Duration))
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
