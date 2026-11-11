package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunAuthenticates(t *testing.T) {
	var queried atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/watchers/login":
			var auth models.WatcherAuthRequest
			if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&auth)) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			assert.Equal(t, "test-machine", *auth.MachineID)
			assert.Equal(t, "test-password", string(*auth.Password))
			// Match LAPI's authentication check, which reports invalid user
			// agents as incorrect credentials.
			if len(strings.Split(r.UserAgent(), "/")) != 2 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			assert.Equal(t, "cs-escalation-controller/"+version, r.UserAgent())
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{
				"token":  "test-token",
				"expire": time.Now().Add(time.Hour).Format(time.RFC3339),
			}))
		case "/v1/alerts":
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
			queried.Store(true)
			assert.NoError(t, json.NewEncoder(w).Encode([]*models.Alert{}))
		default:
			t.Errorf("unexpected endpoint: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Chdir(t.TempDir())
	path := "config.yaml"
	require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("lapi:\n  url: %s\n  username: test-machine\n  password: test-password\ndryRun: true\n", srv.URL)), 0600))
	args := os.Args
	t.Cleanup(func() { os.Args = args })
	os.Args = []string{"cs-escalation-controller", "--config", path, "--once"}

	require.NoError(t, run())
	assert.True(t, queried.Load(), "authenticated alert query was not reached")
}
