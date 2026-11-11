package logging

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/crazy-max/cs-escalation-controller/internal/config"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigureJSON(t *testing.T) {
	out := captureOutput(t)
	require.NoError(t, Configure(config.Cli{
		LogLevel:  "info",
		LogJSON:   true,
		LogCaller: true,
	}))
	log.Debug().Msg("hidden application message")
	log.Info().Str("ip", "192.0.2.1").Msg("application message")
	logrus.Debug("hidden SDK message")
	logrus.WithField("attempt", 1).Warn("SDK message")

	data, err := os.ReadFile(out.Name())
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 1)
	var application map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &application))
	assert.Equal(t, "info", application["level"])
	assert.Equal(t, "application message", application["message"])
	assert.Equal(t, "192.0.2.1", application["ip"])
	assert.NotEmpty(t, application["time"])
	assert.Contains(t, application["caller"], "logger_test.go:")
}

func TestConfigureConsole(t *testing.T) {
	cases := []struct {
		name       string
		noColor    bool
		envNoColor bool
	}{
		{
			name:    "flag",
			noColor: true,
		},
		{
			name:       "NO_COLOR environment",
			envNoColor: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.envNoColor {
				t.Setenv("NO_COLOR", "1")
			}
			out := captureOutput(t)
			require.NoError(t, Configure(config.Cli{
				LogLevel:   "debug",
				LogNoColor: tc.noColor,
			}))
			log.Debug().Msg("console application")
			logrus.Debug("console SDK")
			logrus.Error("SDK error")
			data, err := os.ReadFile(out.Name())
			require.NoError(t, err)
			assert.Contains(t, string(data), "console application")
			assert.NotContains(t, string(data), "SDK")
			assert.NotContains(t, string(data), "\x1b[")
			assert.NotContains(t, string(data), `"level":`)
		})
	}
}

func TestConfigureErrorStack(t *testing.T) {
	out := captureOutput(t)
	require.NoError(t, Configure(config.Cli{
		LogLevel: "info",
		LogJSON:  true,
	}))
	cause := errors.New("failure")
	err := errors.Wrap(cause, "operation")
	require.ErrorIs(t, err, cause)
	log.Error().Stack().Err(err).Send()
	data, readErr := os.ReadFile(out.Name())
	require.NoError(t, readErr)
	var event map[string]any
	require.NoError(t, json.Unmarshal(data, &event))
	assert.Equal(t, "operation: failure", event["error"])
	assert.NotEmpty(t, event["stack"])
}

func TestConfigureRejectsInvalidLevel(t *testing.T) {
	out := captureOutput(t)
	require.NoError(t, Configure(config.Cli{
		LogLevel: "info",
		LogJSON:  true,
	}))
	require.ErrorContains(t, Configure(config.Cli{
		LogLevel: "invalid",
	}), "invalid log level")
	log.Info().Msg("previous configuration remains usable")
	data, err := os.ReadFile(out.Name())
	require.NoError(t, err)
	assert.Contains(t, string(data), `"message":"previous configuration remains usable"`)
}

func captureOutput(t *testing.T) *os.File {
	t.Helper()
	out, err := os.CreateTemp(t.TempDir(), "logging")
	require.NoError(t, err)
	previousOutput := os.Stdout
	previousLogger := log.Logger
	previousStackMarshaler := zerolog.ErrorStackMarshaler
	previousSDKLevel := logrus.GetLevel()
	previousSDKOutput := logrus.StandardLogger().Out
	os.Stdout = out
	logrus.SetOutput(out)
	t.Cleanup(func() {
		os.Stdout = previousOutput
		log.Logger = previousLogger
		zerolog.ErrorStackMarshaler = previousStackMarshaler
		logrus.SetLevel(previousSDKLevel)
		logrus.SetOutput(previousSDKOutput)
		assert.NoError(t, out.Close())
	})
	return out
}
