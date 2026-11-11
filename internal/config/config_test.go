package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
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
			extra: "resetAfter: 2160h\nescalation:\n  baseDuration: 1h\n  multiplier: 3\n  maxDuration: 2h\n",
		},
		{
			name:  "disable reset",
			extra: "resetAfter: '0'\n",
		},
		{
			name:  "partial escalation keeps defaults",
			extra: "escalation:\n  multiplier: 2\n",
		},
		{
			name:      "maximum below base",
			extra:     "escalation:\n  maxDuration: 1h\n",
			wantError: true,
		},
		{
			name:  "maximum equals base",
			extra: "escalation:\n  baseDuration: 4h\n  maxDuration: 4h\n",
		},
		{
			name:      "zero base",
			extra:     "escalation:\n  baseDuration: 0s\n",
			wantError: true,
		},
		{
			name:      "negative base",
			extra:     "escalation:\n  baseDuration: -1h\n",
			wantError: true,
		},
		{
			name:      "non-growing multiplier",
			extra:     "escalation:\n  multiplier: 1\n",
			wantError: true,
		},
		{
			name:      "fractional multiplier",
			extra:     "escalation:\n  multiplier: 1.5\n",
			wantError: true,
		},
		{
			name:      "negative reset",
			extra:     "resetAfter: -1h\n",
			wantError: true,
		},
		{
			name:      "invalid duration",
			extra:     "escalation:\n  baseDuration: tomorrow\n",
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
			if tc.name == "safe defaults" || tc.name == "partial escalation keeps defaults" {
				assert.Equal(t, 720*time.Hour, time.Duration(cfg.ResetAfter))
				assert.Equal(t, Escalation{
					BaseDuration: strfmt.Duration(4 * time.Hour),
					Multiplier:   2,
					MaxDuration:  strfmt.Duration(720 * time.Hour),
				}, cfg.Escalation)
			}
			if tc.name == "custom policy" {
				assert.Equal(t, 2160*time.Hour, time.Duration(cfg.ResetAfter))
				assert.Equal(t, Escalation{
					BaseDuration: strfmt.Duration(time.Hour),
					Multiplier:   3,
					MaxDuration:  strfmt.Duration(2 * time.Hour),
				}, cfg.Escalation)
			}
			if tc.name == "disable reset" {
				assert.Zero(t, time.Duration(cfg.ResetAfter))
			}
			if tc.name == "maximum equals base" {
				assert.Equal(t, 4*time.Hour, time.Duration(cfg.Escalation.BaseDuration))
				assert.Equal(t, time.Duration(cfg.Escalation.BaseDuration), time.Duration(cfg.Escalation.MaxDuration))
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

func TestConfigDurations(t *testing.T) {
	for _, tc := range []struct {
		name      string
		value     string
		want      time.Duration
		wantError bool
	}{
		{
			name:  "days",
			value: "30d",
			want:  720 * time.Hour,
		},
		{
			name:  "weeks",
			value: "2w",
			want:  14 * 24 * time.Hour,
		},
		{
			name:  "combined units",
			value: "1w2d12h",
			want:  228 * time.Hour,
		},
		{
			name:  "fractional days",
			value: "1.5d",
			want:  36 * time.Hour,
		},
		{
			name:      "nonzero duration requires a unit",
			value:     "3600000000000",
			wantError: true,
		},
		{
			name:      "invalid unit",
			value:     "1mo",
			wantError: true,
		},
		{
			name:      "overflow",
			value:     "999999999999999999d",
			wantError: true,
		},
		{
			name:      "negative days",
			value:     "-1d",
			wantError: true,
		},
	} {
		for _, source := range []string{"file", "environment"} {
			t.Run(tc.name+"/"+source, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "config.yaml")
				data := "lapi:\n  url: http://crowdsec:8080\n  username: test\n  password: test\n"
				if source == "file" {
					data += "resetAfter: " + tc.value + "\nescalation:\n  baseDuration: " + tc.value + "\n  maxDuration: " + tc.value + "\n"
				} else {
					t.Setenv("CSEC_ESCALATION_BASEDURATION", tc.value)
					t.Setenv("CSEC_ESCALATION_MAXDURATION", tc.value)
					t.Setenv("CSEC_RESETAFTER", tc.value)
				}
				require.NoError(t, os.WriteFile(path, []byte(data), 0600))
				cfg, err := Load(path)
				if tc.wantError {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tc.want, time.Duration(cfg.Escalation.BaseDuration))
				assert.Equal(t, tc.want, time.Duration(cfg.Escalation.MaxDuration))
				assert.Equal(t, tc.want, time.Duration(cfg.ResetAfter))
			})
		}
	}
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
	t.Setenv("CSEC_ESCALATION_BASEDURATION", "1h")
	t.Setenv("CSEC_ESCALATION_MULTIPLIER", "3")
	t.Setenv("CSEC_ESCALATION_MAXDURATION", "2h")
	t.Setenv("CSEC_RESETAFTER", "2160h")
	t.Setenv("CSEC_EXCLUDESCENARIOS", "crowdsecurity/http-probing,crowdsecurity/ssh-bf")
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("lapi:\n  url: http://crowdsec:8080\n  username: test\n  password: file-value\n"), 0600))
	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, " secret\\new\n${LITERAL} ", cfg.LAPI.Password)
	assert.False(t, cfg.DryRun)
	assert.Equal(t, Escalation{
		BaseDuration: strfmt.Duration(time.Hour),
		Multiplier:   3,
		MaxDuration:  strfmt.Duration(2 * time.Hour),
	}, cfg.Escalation)
	assert.Equal(t, 2160*time.Hour, time.Duration(cfg.ResetAfter))
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
	t.Setenv("CSEC_ESCALATION_MULTIPLIER", "1")
	_, err = Load("")
	require.ErrorContains(t, err, "must be at least 2")
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
	assert.Equal(t, 4*time.Hour, time.Duration(cfg.Escalation.BaseDuration))
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
