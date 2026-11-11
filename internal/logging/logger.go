package logging

import (
	"io"
	"os"
	"time"

	"github.com/crazy-max/cs-escalation-controller/internal/config"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
	"github.com/sirupsen/logrus"
)

// Configure sets up application logging and silences CrowdSec SDK logging.
func Configure(cli config.Cli) error {
	level, err := zerolog.ParseLevel(cli.LogLevel)
	if err != nil {
		return errors.Wrap(err, "invalid log level")
	}

	var out io.Writer = os.Stdout
	if !cli.LogJSON {
		_, noColor := os.LookupEnv("NO_COLOR")
		out = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			NoColor:    noColor || cli.LogNoColor,
			TimeFormat: time.RFC1123,
		}
	}

	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	ctx := zerolog.New(out).Level(level).With().Timestamp()
	if cli.LogCaller {
		ctx = ctx.Caller()
	}
	log.Logger = ctx.Logger()

	// Avoid SDK HTTP dumps, even when application debug logging is enabled.
	logrus.SetLevel(logrus.PanicLevel)
	logrus.SetOutput(io.Discard)

	return nil
}
