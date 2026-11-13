# Changelog

## 0.2.0 (2026/11/13)

* Support day and week durations by @crazy-max in #15
* Preserve scenario and source context by @crazy-max in #16
* Add escalation provenance metadata by @crazy-max in #16

**Full Changelog**: [`v0.1.0...v0.2.0`](https://github.com/crazy-max/cs-escalation-controller/compare/v0.1.0...v0.2.0)

## 0.1.0 (2026/11/11)

* Initial release.
* Monitor local ban decisions through the CrowdSec decisions stream.
* Escalate repeat offenses exponentially with a configurable base duration, multiplier, and maximum duration.
* Group overlapping alerts into one ban episode and preserve longer existing bans.
* Persist per-IP history across restarts and reset after a configurable quiet period, excluding time spent banned.
* Support dry-run mode, scenario exclusions, and CrowdSec allowlist checks.
* Configure through YAML and environment variables, with credential file support.
* Provide standalone binaries and multi-platform container images.
