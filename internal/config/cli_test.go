package config

import (
	"testing"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoggingFlagsOverrideEnvironment(t *testing.T) {
	t.Setenv("LOG_LEVEL", "warn")
	t.Setenv("LOG_JSON", "true")
	t.Setenv("LOG_CALLER", "true")
	t.Setenv("LOG_NOCOLOR", "true")
	cases := []struct {
		name  string
		args  []string
		level string
		json  bool
	}{
		{
			name:  "environment",
			level: "warn",
			json:  true,
		},
		{
			name:  "flags override environment",
			args:  []string{"--log-level=debug", "--log-json=false"},
			level: "debug",
			json:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cli Cli
			parser, err := kong.New(&cli, kong.Vars{"version": "test"})
			require.NoError(t, err)
			_, err = parser.Parse(tc.args)
			require.NoError(t, err)
			assert.Equal(t, tc.level, cli.LogLevel)
			assert.Equal(t, tc.json, cli.LogJSON)
			assert.True(t, cli.LogCaller)
			assert.True(t, cli.LogNoColor)
		})
	}
}
