package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamClient(t *testing.T) {
	for _, startup := range []bool{true, false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/v1/decisions/stream", r.URL.Path)
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "test-key", r.Header.Get("X-Api-Key"))
			assert.Empty(t, r.Header.Get("Authorization"))
			assert.Equal(t, "cs-escalation-controller/test", r.UserAgent())
			assert.Equal(t, startup, r.URL.Query().Get("startup") == "true")
			assert.Equal(t, "crowdsec", r.URL.Query().Get("origins"))
			assert.Equal(t, "Ip", r.URL.Query().Get("scopes"))
			assert.Equal(t, "false", r.URL.Query().Get("community_pull"))
			assert.Equal(t, "false", r.URL.Query().Get("additional_pull"))
			assert.NoError(t, json.NewEncoder(w).Encode(models.DecisionsStreamResponse{
				New: []*models.Decision{{ID: 42}},
			}))
		}))
		client, err := NewStreamClient(srv.URL, "test-key", "cs-escalation-controller/test")
		require.NoError(t, err)
		changes, err := client.Decisions(t.Context(), startup)
		require.NoError(t, err)
		require.Len(t, changes.New, 1)
		assert.EqualValues(t, 42, changes.New[0].ID)
		srv.Close()
	}
}

func TestStreamRequiresKey(t *testing.T) {
	_, err := NewStreamClient("http://localhost:8080", "", "test/1")
	require.ErrorContains(t, err, "lapi.bouncerAPIKey")
}

func TestStreamRejectsRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decisions/stream" {
			t.Error("stream followed a redirect")
		}
		http.Redirect(w, r, "/other", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	client, err := NewStreamClient(srv.URL, "test-key", "test/1")
	require.NoError(t, err)
	_, err = client.Decisions(t.Context(), true)
	require.Error(t, err)
}
