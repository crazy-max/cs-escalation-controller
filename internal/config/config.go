package config

import (
	"net/url"
	"strings"
	"time"

	"github.com/crazy-max/cron/v3"
	"github.com/crazy-max/gonfig"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

type Config struct {
	LAPI             LAPI          `yaml:"lapi"`
	Database         string        `yaml:"database"`
	DryRun           bool          `yaml:"dryRun"`
	Schedule         string        `yaml:"schedule"`
	Escalation       Escalation    `yaml:"escalation"`
	ResetAfter       time.Duration `yaml:"resetAfter"`
	ExcludeScenarios []string      `yaml:"excludeScenarios"`
}

type Escalation struct {
	BaseDuration time.Duration `yaml:"baseDuration"`
	Multiplier   int64         `yaml:"multiplier"`
	MaxDuration  time.Duration `yaml:"maxDuration"`
}

type LAPI struct {
	URL               string `yaml:"url"`
	Username          string `yaml:"username"`
	Password          string `yaml:"password"`
	PasswordFile      string `yaml:"passwordFile"`
	BouncerAPIKey     string `yaml:"bouncerAPIKey"`
	BouncerAPIKeyFile string `yaml:"bouncerAPIKeyFile"`
}

func Load(path string) (Config, error) {
	c := Config{
		Database: "data/state.db",
		DryRun:   true,
		Schedule: "@every 30s",
		Escalation: Escalation{
			BaseDuration: 4 * time.Hour,
			Multiplier:   2,
			MaxDuration:  720 * time.Hour,
		},
		ResetAfter: 720 * time.Hour,
	}
	fileLoader := gonfig.NewFileLoader(gonfig.FileLoaderConfig{
		Filename: path,
		Finder: gonfig.Finder{
			BasePaths: []string{
				"/etc/cs-escalation-controller/config",
				"$XDG_CONFIG_HOME/cs-escalation-controller/config",
				"$HOME/.config/cs-escalation-controller/config",
				"./config",
			},
			Extensions: []string{"yaml", "yml"},
		},
	})
	if found, err := fileLoader.Load(&c); err != nil {
		return c, errors.Wrap(err, "failed to decode configuration from file")
	} else if found {
		log.Info().Str("file", fileLoader.GetFilename()).Msg("configuration loaded from file")
	} else {
		log.Debug().Msg("no configuration file found")
	}
	envLoader := gonfig.NewEnvLoader(gonfig.EnvLoaderConfig{
		Prefix: "CSEC_",
	})
	if found, err := envLoader.Load(&c); err != nil {
		return c, errors.Wrap(err, "failed to decode configuration from environment variables")
	} else if found {
		log.Info().Int("count", len(envLoader.GetVars())).Msg("configuration loaded from environment variables")
	} else {
		log.Debug().Msg("no CSEC_* environment variables defined")
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	u, err := url.Parse(c.LAPI.URL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("lapi.url must be an HTTP(S) URL without credentials, query or fragment")
	}
	if c.LAPI.Username == "" || c.Database == "" {
		return errors.New("lapi.username and database are required")
	}
	if c.LAPI.Password == "" && c.LAPI.PasswordFile == "" {
		return errors.New("lapi.password or lapi.passwordFile is required")
	}
	if c.LAPI.Password != "" && c.LAPI.PasswordFile != "" {
		return errors.New("lapi.password and lapi.passwordFile are mutually exclusive")
	}
	if c.LAPI.BouncerAPIKey != "" && c.LAPI.BouncerAPIKeyFile != "" {
		return errors.New("lapi.bouncerAPIKey and lapi.bouncerAPIKeyFile are mutually exclusive")
	}
	if _, err := ParseSchedule(c.Schedule); err != nil {
		return err
	}
	if c.Escalation.BaseDuration <= 0 {
		return errors.New("escalation.baseDuration must be positive")
	}
	if c.Escalation.Multiplier < 2 {
		return errors.New("escalation.multiplier must be at least 2")
	}
	if c.Escalation.MaxDuration < c.Escalation.BaseDuration {
		return errors.New("escalation.maxDuration must be at least escalation.baseDuration")
	}
	if c.ResetAfter < 0 {
		return errors.New("resetAfter must be a nonnegative duration (0 disables reset)")
	}
	return nil
}

// ParseSchedule accepts cron expressions with optional seconds and descriptors.
func ParseSchedule(schedule string) (cron.Schedule, error) {
	// cron v3.1.1 slices at the first space when parsing a timezone prefix.
	if (strings.HasPrefix(schedule, "TZ=") || strings.HasPrefix(schedule, "CRON_TZ=")) && !strings.Contains(schedule, " ") {
		return nil, errors.New("invalid schedule: missing expression after timezone")
	}
	parser := cron.NewParser(cron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	parsed, err := parser.Parse(schedule)
	if err != nil {
		return nil, errors.Wrap(err, "invalid schedule")
	}
	return parsed, nil
}
