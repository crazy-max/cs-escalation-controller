package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/crazy-max/cs-escalation-controller/internal/config"
	"github.com/crazy-max/cs-escalation-controller/internal/controller"
	"github.com/crazy-max/cs-escalation-controller/internal/logging"
	"github.com/crazy-max/cs-escalation-controller/internal/secret"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		log.Fatal().Stack().Err(err).Send()
	}
}

func run() error {
	cli := config.Cli{}
	meta := config.Meta{
		ID:      "cs-escalation-controller",
		Name:    "CrowdSec Escalation Controller",
		Desc:    "Escalate CrowdSec bans for repeat offenders",
		URL:     "https://github.com/crazy-max/cs-escalation-controller",
		Author:  "CrazyMax",
		Version: version,
	}

	// LAPI authentication requires a User-Agent with exactly one slash.
	meta.UserAgent = fmt.Sprintf("%s/%s", meta.ID, meta.Version)

	_ = kong.Parse(&cli,
		kong.Name(meta.ID),
		kong.Description(fmt.Sprintf("%s. More info: %s", meta.Desc, meta.URL)),
		kong.UsageOnError(),
		kong.Vars{
			"version": meta.Version,
		},
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
			Summary: true,
		}))

	if err := logging.Configure(cli); err != nil {
		return err
	}

	cfg, err := config.Load(cli.Config)
	if err != nil {
		return err
	}
	lapiPassword, err := secret.GetSecret(cfg.LAPI.Password, cfg.LAPI.PasswordFile)
	if err != nil {
		return errors.Wrap(err, "read LAPI password")
	}
	if lapiPassword == "" {
		return errors.New("LAPI password is empty")
	}

	api, err := controller.NewClient(cfg.LAPI.URL, cfg.LAPI.Username, lapiPassword, meta.UserAgent)
	if err != nil {
		return err
	}

	store, err := controller.OpenStore(cfg.Database, cfg.LAPI.URL, cfg.DryRun, time.Now().UTC())
	if err != nil {
		return err
	}
	defer store.Close()

	c := controller.Controller{
		API:   api,
		Store: store,
		Policy: controller.Policy{
			BaseDuration: cfg.Escalation.BaseDuration,
			Multiplier:   cfg.Escalation.Multiplier,
			MaxDuration:  cfg.Escalation.MaxDuration,
			ResetAfter:   cfg.ResetAfter,
		},
		ExcludeScenarios: cfg.ExcludeScenarios,
		Log:              log.Logger,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if cli.Once {
		return c.Reconcile(ctx)
	}

	bouncerAPIKey, err := secret.GetSecret(cfg.LAPI.BouncerAPIKey, cfg.LAPI.BouncerAPIKeyFile)
	if err != nil {
		return errors.Wrap(err, "read bouncer API key")
	}

	c.Stream, err = controller.NewStreamClient(cfg.LAPI.URL, bouncerAPIKey, meta.UserAgent)
	if err != nil {
		return err
	}

	return c.Start(ctx, cfg.Schedule)
}
