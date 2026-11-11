# Contributing

Contributions are welcome and released under the project's
[MIT license](../LICENSE).

## Development

Fork https://github.com/crazy-max/cs-escalation-controller and create a branch
for your changes.

Use Docker with Buildx and Compose for the commands below. Dependencies are
vendored, so no host Go installation is required. For native Go development,
use the version declared in `go.mod`.

Run checks relevant to your changes:

```sh
docker buildx bake validate
docker buildx bake test
```

Unit tests enable race detection and write coverage to `bin/coverage/coverage.txt`.

Run integration tests against a disposable CrowdSec Local API:

```sh
docker compose -f test/compose.yaml up --build --abort-on-container-exit --exit-code-from tests
docker compose -f test/compose.yaml down --volumes
```

Run cleanup even if tests fail. The stack uses test credentials, an internal
network, and temporary CrowdSec data. Integration coverage is written to
`bin/coverage/integration/coverage.txt` by default.

Build all supported release artifacts and container images:

```sh
docker buildx bake artifact-all image-all
```

When changing Go dependencies, regenerate the vendored dependencies:

```sh
make vendor
```

## Submitting changes

Keep changes focused and include tests for behavior changes. Update the example
configuration and relevant documentation when configuration or behavior changes.

Push your branch to your fork and open a pull request:
https://github.com/crazy-max/cs-escalation-controller/compare

Explain the problem, the resulting behavior, and the checks you ran.
