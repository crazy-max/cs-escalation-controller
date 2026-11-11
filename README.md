<p align="center">
  <a href="https://github.com/crazy-max/cs-escalation-controller" target="_blank">
    <img height="128" src=".github/cs-escalation-controller.png" alt="CrowdSec Escalation Controller">
  </a>
</p>

<p align="center">
  <a href="https://github.com/crazy-max/cs-escalation-controller/releases/latest"><img src="https://img.shields.io/github/release/crazy-max/cs-escalation-controller.svg?style=flat-square" alt="GitHub release"></a>
  <a href="https://github.com/crazy-max/cs-escalation-controller/releases/latest"><img src="https://img.shields.io/github/downloads/crazy-max/cs-escalation-controller/total.svg?style=flat-square" alt="Total downloads"></a>
  <a href="https://github.com/crazy-max/cs-escalation-controller/actions?workflow=build"><img src="https://img.shields.io/github/actions/workflow/status/crazy-max/cs-escalation-controller/build.yml?branch=main&label=build&logo=github&style=flat-square" alt="Build Status"></a>
  <a href="https://hub.docker.com/r/crazymax/cs-escalation-controller/"><img src="https://img.shields.io/docker/stars/crazymax/cs-escalation-controller.svg?style=flat-square&logo=docker" alt="Docker Stars"></a>
  <a href="https://hub.docker.com/r/crazymax/cs-escalation-controller/"><img src="https://img.shields.io/docker/pulls/crazymax/cs-escalation-controller.svg?style=flat-square&logo=docker" alt="Docker Pulls"></a>
  <br /><a href="https://codecov.io/gh/crazy-max/cs-escalation-controller"><img src="https://img.shields.io/codecov/c/github/crazy-max/cs-escalation-controller?logo=codecov&style=flat-square" alt="Codecov"></a>
  <a href="https://github.com/sponsors/crazy-max"><img src="https://img.shields.io/badge/sponsor-crazy--max-181717.svg?logo=github&style=flat-square" alt="Become a sponsor"></a>
  <a href="https://www.paypal.me/crazyws"><img src="https://img.shields.io/badge/donate-paypal-00457c.svg?logo=paypal&style=flat-square" alt="Donate PayPal"></a>
</p>

## About

**CrowdSec Escalation Controller** extends CrowdSec bans for repeat offenders.
It monitors local ban decisions and uses persistent per-IP history to apply
configurable exponential escalation, capped at a maximum duration.

Alerts within the same ban episode count as one offense. Existing longer bans
are preserved, and history resets after a configurable quiet period. Dry-run
mode records what would happen without creating decisions.

Run it as a standalone executable or a [container image](https://hub.docker.com/r/crazymax/cs-escalation-controller/).

> [!NOTE]
> Want to be notified of new releases? Check out 🔔 [Diun (Docker Image Update Notifier)](https://github.com/crazy-max/diun)
> project!

## Documentation

See [config.example.yaml](config.example.yaml) for configuration options and
[CONTRIBUTING.md](.github/CONTRIBUTING.md) for build and test commands.

## Contributing

Want to contribute? Awesome! The most basic way to show your support is to star
the project, or to raise issues. You can also support this project by [**becoming a sponsor on GitHub**](https://github.com/sponsors/crazy-max)
or by making a [PayPal donation](https://www.paypal.me/crazyws) to ensure this
journey continues indefinitely!

Thanks again for your support, it is much appreciated! :pray:

## License

MIT. See `LICENSE` for more details.
