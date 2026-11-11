package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	cases := []struct {
		name      string
		extra     string
		wantError bool
	}{
		{
			name: "safe defaults",
		},
		{
			name:  "custom policy",
			extra: "resetAfter: 2160h\ndurations: [1h, 2h]\n",
		},
		{
			name:  "disable reset",
			extra: "resetAfter: '0'\n",
		},
		{
			name:  "empty ladder keeps defaults",
			extra: "durations: []\n",
		},
		{
			name:      "descending ladder",
			extra:     "durations: [8h, 4h]\n",
			wantError: true,
		},
		{
			name:      "negative reset",
			extra:     "resetAfter: -1h\n",
			wantError: true,
		},
		{
			name:      "invalid duration",
			extra:     "durations: [4h, tomorrow]\n",
			wantError: true,
		},
		{
			name:      "invalid schedule",
			extra:     "schedule: invalid\n",
			wantError: true,
		},
		{
			name:      "empty schedule",
			extra:     "schedule: ''\n",
			wantError: true,
		},
		{
			name:      "timezone without expression",
			extra:     "schedule: CRON_TZ=UTC\n",
			wantError: true,
		},
		{
			name:  "unknown setting ignored",
			extra: "dryrnu: false\n",
		},
		{
			name:      "ambiguous credentials",
			extra:     "  password: also-specified\n",
			wantError: true,
		},
		{
			name:  "only first document loaded",
			extra: "---\ndryRun: false\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			data := "lapi:\n  url: http://crowdsec:8080\n  username: test\n  passwordFile: test\n" + tc.extra
			require.NoError(t, os.WriteFile(path, []byte(data), 0600))
			cfg, err := Load(path)
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.True(t, cfg.DryRun)
			assert.Equal(t, "@every 30s", cfg.Schedule)
			if tc.name == "safe defaults" || tc.name == "empty ladder keeps defaults" {
				assert.Equal(t, 720*time.Hour, cfg.ResetAfter)
				assert.Equal(t, []time.Duration{
					4 * time.Hour,
					8 * time.Hour,
					12 * time.Hour,
					24 * time.Hour,
					168 * time.Hour,
					720 * time.Hour,
				}, cfg.Durations)
			}
			if tc.name == "custom policy" {
				assert.Equal(t, 2160*time.Hour, cfg.ResetAfter)
				assert.Equal(t, []time.Duration{time.Hour, 2 * time.Hour}, cfg.Durations)
			}
			if tc.name == "disable reset" {
				assert.Zero(t, cfg.ResetAfter)
			}
		})
	}
}

func TestConfigLiteralPassword(t *testing.T) {
	t.Setenv("ESC_TEST_PASSWORD", "must-not-be-used")
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := "lapi:\n  url: http://crowdsec:8080\n  username: test\n  password: '${ESC_TEST_PASSWORD} $plain $$literal \\new'\n"
	require.NoError(t, os.WriteFile(path, []byte(data), 0600))
	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, `${ESC_TEST_PASSWORD} $plain $$literal \new`, cfg.LAPI.Password)
}

func TestConfigQuotedScalars(t *testing.T) {
	for _, literal := range []string{"012345", "0x1F", "1e3", "1.10", "True", "2024-01-01"} {
		t.Run(literal, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			data := "lapi:\n  url: http://crowdsec:8080\n  username: '007'\n  password: '" + literal + "'\ndryRun: true\n"
			require.NoError(t, os.WriteFile(path, []byte(data), 0600))
			cfg, err := Load(path)
			require.NoError(t, err)
			assert.Equal(t, "007", cfg.LAPI.Username)
			assert.Equal(t, literal, cfg.LAPI.Password)
			assert.True(t, cfg.DryRun)
		})
	}
}

func TestConfigEnvironmentOverrides(t *testing.T) {
	t.Setenv("CSEC_LAPI_PASSWORD", " secret\\new\n${LITERAL} ")
	t.Setenv("CSEC_DRYRUN", "false")
	t.Setenv("CSEC_RESETAFTER", "2160h")
	t.Setenv("CSEC_DURATIONS", "1h,2h")
	t.Setenv("CSEC_EXCLUDESCENARIOS", "crowdsecurity/http-probing,crowdsecurity/ssh-bf")
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("lapi:\n  url: http://crowdsec:8080\n  username: test\n  password: file-value\n"), 0600))
	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, " secret\\new\n${LITERAL} ", cfg.LAPI.Password)
	assert.False(t, cfg.DryRun)
	assert.Equal(t, 2160*time.Hour, cfg.ResetAfter)
	assert.Equal(t, []time.Duration{time.Hour, 2 * time.Hour}, cfg.Durations)
	assert.Equal(t, []string{"crowdsecurity/http-probing", "crowdsecurity/ssh-bf"}, cfg.ExcludeScenarios)
}

func TestConfigEnvironmentOnly(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("CSEC_LAPI_URL", "http://crowdsec:8080")
	t.Setenv("CSEC_LAPI_USERNAME", "test")
	t.Setenv("CSEC_LAPI_PASSWORDFILE", "/run/secrets/password")
	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, "/run/secrets/password", cfg.LAPI.PasswordFile)
	assert.True(t, cfg.DryRun)
	t.Setenv("CSEC_DRYRUN", "invalid")
	_, err = Load("")
	require.ErrorContains(t, err, "environment variables")
	t.Setenv("CSEC_DRYRUN", "true")
	t.Setenv("CSEC_DURATIONS", "8h,4h")
	_, err = Load("")
	require.ErrorContains(t, err, "strictly increasing")
}

func TestConfigDiscovery(t *testing.T) {
	t.Chdir(t.TempDir())
	require.NoError(t, os.WriteFile("config.yml", []byte("lapi:\n  url: http://crowdsec:8080\n  username: test\n  password: test\n"), 0600))
	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, "test", cfg.LAPI.Username)
}

func TestConfigExample(t *testing.T) {
	cfg, err := Load("../../config.example.yaml")
	require.NoError(t, err)
	assert.Equal(t, "http://crowdsec:8080", cfg.LAPI.URL)
	assert.Equal(t, "replace-me", cfg.LAPI.Password)
	assert.Len(t, cfg.Durations, 6)
}

func TestConfigSchedules(t *testing.T) {
	for _, schedule := range []string{
		"*/5 * * * *",
		"*/30 * * * * *",
		"@every 30s",
		"@hourly",
		"CRON_TZ=UTC 0 * * * *",
	} {
		t.Run(schedule, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			data := "lapi:\n  url: http://crowdsec:8080\n  username: test\n  passwordFile: test\nschedule: '" + schedule + "'\n"
			require.NoError(t, os.WriteFile(path, []byte(data), 0600))
			cfg, err := Load(path)
			require.NoError(t, err)
			assert.Equal(t, schedule, cfg.Schedule)
		})
	}
}

func TestStreamCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("lapi:\n  url: http://localhost:8080\n  username: test\n  password: test\n  bouncerAPIKey: file-key\n"), 0600))
	t.Setenv("CSEC_LAPI_BOUNCERAPIKEY", "environment-key")
	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, "environment-key", cfg.LAPI.BouncerAPIKey)

	cfg.LAPI.BouncerAPIKeyFile = filepath.Join(t.TempDir(), "api-key")
	require.ErrorContains(t, cfg.Validate(), "are mutually exclusive")
	cfg.LAPI.BouncerAPIKey = ""
	require.NoError(t, cfg.Validate())
}
